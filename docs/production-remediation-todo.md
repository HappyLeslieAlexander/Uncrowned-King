# Uncrowned King 生产修复 TODO

> 基线：`v1.0.2` + 当前 HEAD（2026-10-24）
> 范围：把上一轮生产就绪审查中的发现转化为可执行、可验收的修复任务。
> 原则：先修阻断项，再做安全/运维加固，最后处理低风险与文档问题；每一项都必须带回归测试。

---

## ✅ 状态更新（2026-10-24，第二轮修复完成）

以下条目已全部实现并通过回归测试（948 项测试、clippy -D warnings、cargo deny、
helm lint/template + 二进制 config-check、interop-curl TLS/QUIC 双通道全绿）：

- **Wave 1（P0-1～P0-5）全部完成**（P0-3 的 Helm 容量默认值降为 200 sessions×8MiB 并附公式；
  新增 `uncrowned_king_server_global_buffered_bytes/_limit`、`global_active_flows/_limit` gauge）。
- **Wave 2（P1-1～P1-8）全部完成**，其中：
  - P1-4：`PolicySet::evaluate_pre_resolve` 预检，被拒目标不再触发 DNS（deny-all 与
    不可解析域名统一返回 PolicyDenied，关闭 DNS 枚举 oracle）。
  - P1-5：客户端 SIGTERM 上行排空 + `uncrowned_king_client_shutdown_upload_truncated_total`。
  - P1-6：UDP association 改为每目标独立 worker（有界队列、独立 flow 生命周期），
    队列溢出丢弃并计入 `uncrowned_king_client_udp_association_queue_full_total`。
  - P1-8：server.config 顶层字段白名单 + `scripts/helm-config-check.sh`（渲染 TOML →
    真实二进制 config-check + 拼写错误负向断言，已接入 CI）。
- **Wave 3（P2-1～P2-12）全部完成**，备注：
  - P2-1 采用方案 B（文档化 16KiB UDP 上限与两端匹配要求，见 docs/tuning.md §1.1.1）。
  - P2-3 client ServiceMonitor 需 `serviceMonitor.client.enabled` + `client.service.enabled`。
  - P2-12 Docker smoke（`scripts/docker-smoke.sh`）已接入 CI（本仓库开发机无 Docker，
    运行时行为以 CI 为准）。
  - tokio 升级至 1.53.3（RUSTSEC-2026-0386/0384）。

剩余未做（原清单之外的新增发现）：
- `docs/spec-v1.0.md` 与 `docs/architecture.md` 的 SETTINGS 方向已按实现（双向）更新时序图；
  spec 正文 "Peers must send" 与实现一致，无需加注。
- 版本号同步与 GPG 签名发布走 `publish-release` runbook，不在本轮范围。

---

## 0. 使用方式与总体验收标准

### 0.1 优先级定义

| 级别 | 含义 | 处理要求 |
|---|---|---|
| **P0** | 会导致生产不可用、部署死锁、全局资源耗尽或明显的部署安全暴露 | 上线前必须完成 |
| **P1** | 高概率的生产故障、协议不兼容、轮换失效或重要安全加固 | 首个生产版本必须完成，或经书面风险接受 |
| **P2** | 可靠性、性能、可观测性、文档与边界问题 | 可排入后续迭代，但需记录 |

### 0.2 每个任务的完成定义（DoD）

- [ ] 代码修改已合入，且不引入 `unsafe`。
- [ ] 新增/更新单元测试、集成测试或 e2e 测试；测试不得依赖固定的短 `sleep`，应使用确定性同步或 poll-with-timeout。
- [ ] `cargo fmt --all --check` 通过。
- [ ] `cargo check --workspace --locked` 通过。
- [ ] `cargo test --workspace --locked` 通过。
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` 通过。
- [ ] 如涉及配置/部署：Helm 渲染 + `uk-server/uk-client config-check` 通过；Docker/K8s smoke 通过。
- [ ] 如涉及指标/告警：`/metrics` 输出仍符合 Prometheus 文本格式，dashboard/alert 已同步。
- [ ] 文档（README、operations、key-management、chart values/README）已更新。
- [ ] 有回滚方案；涉及协议/配置变更的，说明兼容性。

### 0.3 发布门禁（建议加入 CI / release checklist）

- [ ] `helm template` 渲染出的 server/client TOML 能通过对应二进制的 `config-check`。
- [ ] 客户端在“无任何 SOCKS 流量”的情况下 `/readyz` 能变绿；空闲超过 `idle_timeout_seconds` 后仍能自愈。
- [ ] Kubernetes Service 场景下，冷启动和滚动更新不会因 readiness 形成 Endpoints 死锁。
- [ ] Docker 文档中的命令在 Linux 上可复制执行成功（含配置/证书/策略挂载与 UID 权限）。
- [ ] `max_sessions × max_buffered_bytes_per_session` 与 Pod memory limit 匹配；`LimitNOFILE` 与 flow 上限匹配。
- [ ] `networkPolicy.enabled=true` 时，客户端 ingress/egress 不再对全部 namespace/任意 443 开放。
- [ ] 至少一个“规范第三方客户端”互操作测试通过，或明确记录当前 SETTINGS 为 server-only 扩展。

---

## 1. P0：上线前必须完成

### P0-1 修复客户端 `/readyz` 死锁（Service / 滚动更新）

**问题**

`ClientMetrics::is_ready()` 要求 `active_sessions > 0`，但客户端没有启动预热；只有收到 SOCKS 请求才会建立 carrier。保活又只在有 open flow 时发 PING，空闲 session 会被服务端 `idle_timeout_seconds` 关闭。结果：

```text
启动 → 无 session → /readyz 503
无流量 → 无 Endpoints → 永远没有第一个 SOCKS 请求
空闲 5 分钟 → session 被服务端关闭 → /readyz 503 → 再次死锁
```

**涉及文件**

- [crates/uk-client/src/observability.rs](../crates/uk-client/src/observability.rs:105)
- [crates/uk-client/src/relay/listener.rs](../crates/uk-client/src/relay/listener.rs:108)
- [crates/uk-client/src/relay/session_manager.rs](../crates/uk-client/src/relay/session_manager.rs:335)
- [crates/uk-client/src/relay/carrier.rs](../crates/uk-client/src/relay/carrier.rs:180)
- Helm/standalone readiness probes

**实现选项（推荐 A + B）**

- [ ] **A. 后台 session maintainer**
  - [ ] 在 `run_socks5_listener_on_until_shutdown_inner` 启动后，spawn 一个受 shutdown 管理的 maintainer task。
  - [ ] maintainer 调用 `ClientSessionManager::connect_and_pool()` 建立至少一条健康 session；失败时使用现有指数退避 + jitter，成功后等待 session 关闭再重连。
  - [ ] 该 task 必须纳入 `ClientSessionManager` 的生命周期（shutdown 时 join/abort），不能是 detached task。
  - [ ] 复用 `connect_lock` / `config_publish_lock`，避免与按需连接竞争。
- [ ] **B. 健康 session 的空闲保活**
  - [ ] 给健康 session 增加 `keepalive_when_idle` 标记（或单独的 `ClientSession::is_health_session`）。
  - [ ] `spawn_keepalive` 对健康 session 即使 `has_open_flows() == false` 也发送 PING；普通业务 session 仍遵守“无流不发 PING”的省资源策略。
  - [ ] 或：maintainer 在 session 被 idle 关闭后立即重连；但 ready 会短暂抖动，需评估是否可接受。
- [ ] **C. 备选：解耦 readiness**
  - [ ] 若产品决定 readiness 只表示“本地监听器可用”，则 `is_ready()` 只返回 `ready`，另增 `uncrowned_king_client_upstream_connected` gauge 与告警。
  - [ ] 该方案必须在文档中明确：Ready 不代表上游可用，K8s Service 可能把请求路由到暂时无法连接服务端的客户端。

**测试**

- [ ] e2e：启动 client + server，**不发送任何 SOCKS 请求**，轮询 `/readyz` 直到 200（带超时）。
- [ ] e2e：server `idle_timeout_seconds=2`，建立 session 后等待超过 idle，断言 `/readyz` 保持 200（maintainer 重连或 PING 保活）。
- [ ] e2e：停止 server → `/readyz` 503；重启 server → 无需 SOCKS 流量，`/readyz` 自动恢复 200。
- [ ] K8s smoke（kind 或现有集群）：Deployment 冷启动、滚动更新、空闲 5 分钟后 Service 仍有 Endpoints。
- [ ] 测试不得用固定短 sleep；使用 `tokio::time::timeout` + 轮询/条件等待。

**验收**

- [ ] 新 Pod 在没有任何业务流量时能通过 readiness。
- [ ] 空闲超过 server idle timeout 后，readiness 不会永久失败。
- [ ] 服务端重启后，客户端可自行恢复，不依赖外部 SOCKS 请求触发。
- [ ] maintainer 在 shutdown 时干净退出，不阻止进程退出。

**风险/回滚**

- 后台连接会增加一条常驻 carrier；需确认 server `max_sessions` 预算。
- 若采用“健康 session PING”，需确认不违背“避免空闲 session 常驻”的协议建议；可在文档中说明这是实现层的健康检查例外。

---

### P0-2 服务端配置增加 wire SETTINGS 上限校验

**问题**

`ServerConfig::validate_limits()` 没有校验 `max_streams`、`max_udp_flows`、`idle_timeout_seconds` 是否在 `uk-proto` 的协商上限内。`server_settings()` 会把这些值发给客户端，而客户端 `Settings::negotiated_v1_0()` 会拒绝超限值，导致认证成功后立即失败；服务端 `/readyz` 仍为 200。

**实测**

```text
server config-check: ok   # max_streams=2000000, max_udp_flows=2000000, idle_timeout=31536000
client: invalid settings: max_streams
server: auth.success → server.session.peer_closed
```

**涉及文件**

- [crates/uk-server/src/config.rs](../crates/uk-server/src/config.rs:118)
- [crates/uk-server/src/lib.rs](../crates/uk-server/src/lib.rs:1458)
- [crates/uk-proto/src/settings.rs](../crates/uk-proto/src/settings.rs:197)
- `MAX_NEGOTIATED_FLOWS` / `MAX_NEGOTIATED_IDLE_TIMEOUT_SECONDS` 常量

**实现**

- [ ] 在 `validate_limits()` 中增加：
  - [ ] `max_streams <= MAX_NEGOTIATED_FLOWS`
  - [ ] `max_udp_flows <= MAX_NEGOTIATED_FLOWS`
  - [ ] `idle_timeout_seconds <= MAX_NEGOTIATED_IDLE_TIMEOUT_SECONDS`
- [ ] 错误信息明确包含字段名、当前值和上限，便于 `config-check` 定位。
- [ ] 为 `next_idle_deadline()` 增加防御：`checked_add` 失败时不要退化为 `Instant::now()` 导致立即 idle；要么返回 `None`（禁用 idle），要么拒绝启动（推荐由配置上限保证）。
- [ ] 评估是否为其他 timeout 增加合理上限：
  - [ ] `handshake_timeout_seconds`
  - [ ] `target_connect_timeout_seconds`
  - [ ] `tcp_half_close_timeout_seconds`
  - [ ] `carrier_write_timeout_seconds`
  - [ ] `udp_flow_idle_timeout_seconds`
  - [ ] `shutdown_timeout_seconds`
  - [ ] `replay_cache_window_seconds`
- [ ] 复用 `uk-proto` 的常量，避免在 server 内复制魔数。

**测试**

- [ ] 单元测试：`max_streams = MAX_NEGOTIATED_FLOWS + 1` → `validate_limits` 失败。
- [ ] 单元测试：`max_udp_flows = MAX_NEGOTIATED_FLOWS + 1` → 失败。
- [ ] 单元测试：`idle_timeout_seconds = MAX_NEGOTIATED_IDLE_TIMEOUT_SECONDS + 1` → 失败。
- [ ] 单元测试：边界值 `MAX_NEGOTIATED_FLOWS` / 30 天 → 通过。
- [ ] 回归测试：对默认配置和一组边界配置，`server_settings().negotiated_v1_0()` 必须成功（服务端生成的 SETTINGS 必须可被客户端接受）。
- [ ] e2e：用边界配置启动 server + client，完成一次 TCP/UDP 握手。
- [ ] `config-check` 集成测试：上述超限配置必须返回非零退出码。

**验收**

- [ ] 任何能通过 `uk-server config-check` 的配置，服务端发出的 SETTINGS 都能被本仓库客户端接受。
- [ ] 配置错误在启动/`config-check` 阶段失败，而不是在客户端握手中失败。
- [ ] 服务端 `/readyz` 不再对“配置自相矛盾”的实例返回 200。

---

### P0-3 增加全局内存 / FD 预算，并修正 Helm 默认容量

**问题**

服务端只有 per-session/per-flow 字节预算，没有全局内存预算。Helm 默认：

```yaml
memory: 2Gi
max_sessions: 10000
max_buffered_bytes_per_session: 16777216
```

理论最坏：

```text
10,000 × 16 MiB = 156 GiB
```

约 128 个满缓冲 session 就能耗尽 2 GiB；`max_streams=1024` 还会带来大量目标 socket / FD。有效凭据（或被窃取凭据）即可触发，目标读取慢时缓冲会真实占用。

**涉及文件**

- [deploy/helm/uncrowned-king/values.yaml](../deploy/helm/uncrowned-king/values.yaml:67)
- [crates/uk-server/src/config.rs](../crates/uk-server/src/config.rs:340)
- [crates/uk-server/src/relay/context.rs](../crates/uk-server/src/relay/context.rs:540)
- [crates/uk-server/src/relay/tasks.rs](../crates/uk-server/src/relay/tasks.rs:501)
- [docs/operations.md](../docs/operations.md:24)

**实现（分两步）**

- [ ] **短期：修正 Helm 默认值与文档**
  - [ ] 根据 `resources.limits.memory` 反推 `max_sessions`，例如 2 GiB 下默认 `max_sessions=100`～`200`，并同步降低 `max_buffered_bytes_per_session`。
  - [ ] 在 `values.yaml` 注释中给出公式：`max_sessions × max_buffered_bytes_per_session + 固定开销 < memory limit`。
  - [ ] 在 `docs/operations.md` 更新容量表，明确“per-session 上限不等于全局上限”。
  - [ ] 检查 `LimitNOFILE` 与 `max_sessions × max_streams` 的关系。
- [ ] **中期：代码级全局预算**
  - [ ] 新增 `max_total_buffered_bytes`（或 `max_total_flows`）配置项，默认值需有安全上限。
  - [ ] 在 `ServerRuntime`/`ConnectionRuntime` 中共享一个全局 `AtomicUsize` 或 `Semaphore`。
  - [ ] `BufferedTargetData` 在预留 per-flow/per-session 之前或之后，同时预留全局额度；任何失败路径都必须释放（Drop）。
  - [ ] 全局额度耗尽时，向客户端返回 `RESOURCE_LIMIT` + `TCP_CLOSE(error)`，而不是 OOM。
  - [ ] 为流表增加全局 flow 计数/信号量，避免 `max_sessions × max_streams` 无界。
- [ ] **可选：按内存自动推导**
  - [ ] 启动时读取 cgroup memory limit，若配置未显式设置，则按比例计算 `max_sessions`/`max_buffered`；注意不要在非容器环境误判。
  - [ ] 若实现自动推导，必须在日志/`config-check` 中打印最终生效值。

**测试**

- [ ] 单元测试：全局预算耗尽时返回 `RESOURCE_LIMIT`，Drop 后额度恢复。
- [ ] 单元测试：多 session 并发填缓冲，全局计数不超过上限。
- [ ] soak：多客户端持续上传、慢目标读取，观察 RSS 稳定在 memory limit 以下。
- [ ] FD 测试：大量流打开/关闭，`/proc/<pid>/fd` 不持续增长，接近 `LimitNOFILE` 前有可观测告警。
- [ ] Helm 渲染测试：默认 values 下的理论内存上界小于 `resources.limits.memory`。

**验收**

- [ ] 在最坏输入下，进程内存/FD 由配置硬约束，而不是依赖内核 OOM 或 ulimit。
- [ ] Helm 默认配置不会在少量满缓冲 session 下 OOM。
- [ ] 资源耗尽表现为受控的 `RESOURCE_LIMIT`，不是进程崩溃。

---

### P0-4 Kubernetes 客户端网络暴露与可发现性

**问题**

Helm 客户端固定 `--listen 0.0.0.0:1080 --allow-non-loopback`，SOCKS 无认证；NetworkPolicy ingress 对所有 namespace 开放；egress 只限定端口，允许任意 443/8443。被攻陷的客户端 Pod 可以：

1. 作为集群内开放 SOCKS 代理被任意 Pod 使用；
2. 绕过 UK 直连任意内网 443/8443 服务。

同时 Helm 没有 client Service；`kind: Deployment` 且 `hostPort: null` 时没有稳定发现方式。

**涉及文件**

- [deploy/helm/uncrowned-king/templates/client-daemonset.yaml](../deploy/helm/uncrowned-king/templates/client-daemonset.yaml:99)
- [deploy/helm/uncrowned-king/templates/network-policy.yaml](../deploy/helm/uncrowned-king/templates/network-policy.yaml:82)
- [deploy/kubernetes/uncrowned-king-client.yaml](../deploy/kubernetes/uncrowned-king-client.yaml:126)
- `deploy/helm/uncrowned-king/values.yaml`

**实现**

- [ ] 明确客户端形态：
  - [ ] **local sidecar**：绑定 `127.0.0.1:1080`，不创建 Service/hostPort，NetworkPolicy 只允许同 Pod/本机。
  - [ ] **cluster proxy**：显式 `client.socks5.exposure=cluster`，才绑定 `0.0.0.0`，并强制 NetworkPolicy 白名单。
- [ ] 新增 `client.socks5.listen`（或 `listenAddress`）values，模板把它传给 `--listen`，不要写死 `0.0.0.0`。
- [ ] 新增可选的 `client.service`（ClusterIP）模板；当 `kind=Deployment` 或需要稳定 DNS 时启用。
- [ ] 新增 `networkPolicy.client.ingress.namespaces` / `podSelector` values；默认只允许同 namespace 或显式白名单，禁止 `namespaceSelector: {}`。
- [ ] 客户端 egress：
  - [ ] DNS 只允许到 cluster DNS（见 P1-7）。
  - [ ] carrier 流量用 `to` 限定到 server 的 namespace/pod label，而不是任意 443/8443。
  - [ ] 不提供“任意 443”作为默认值。
- [ ] 更新 values 注释与 README：明确 SOCKS5 无认证，`0.0.0.0`/hostPort 的风险。
- [ ] 如果产品要求集群共享代理，建议在架构上增加 SOCKS 认证或前置 mTLS；仅靠 NetworkPolicy 是边界防护，不是身份认证。

**测试**

- [ ] `helm template` 断言：默认渲染不包含 `--allow-non-loopback`/`0.0.0.0`（sidecar 模式）。
- [ ] `helm template` 断言：cluster 模式必须显式开启，且 NetworkPolicy 生成最小白名单。
- [ ] NetworkPolicy 测试：从非白名单 namespace 访问 1080 应被拒绝；白名单 namespace 可访问。
- [ ] Egress 测试：客户端 Pod 不能直连一个测试内网 443 服务（除非显式加入白名单）。
- [ ] K8s smoke：Deployment + Service 可以通过 Service DNS 使用 SOCKS；滚动更新期间 Endpoints 正常。

**验收**

- [ ] 默认安装不会把无认证 SOCKS 暴露给整个集群。
- [ ] 客户端 Pod 不具备“任意 443 直连”能力。
- [ ] 需要集群代理时，有明确开关、白名单和文档。

---

### P0-5 修复 Docker 文档与镜像运行方式

**问题**

README 的 Docker 命令只挂载 TOML，但示例配置引用证书、私钥、策略和 CA；示例 `listen=127.0.0.1` 在容器内无法通过 `-p` 访问；镜像以 UID 65532 运行，而宿主机 0600 文件通常属于宿主用户，Linux 上不可读。文档命令按原样执行会失败。

**涉及文件**

- [Dockerfile](../Dockerfile:23)
- [README.md](../README.md:363)
- [examples/server.toml](../examples/server.toml:3)
- [examples/client.toml](../examples/client.toml:10)

**实现**

- [ ] 新增 Docker 专用示例目录（例如 `examples/docker/`）：
  - [ ] `server.toml` 使用 `listen = "0.0.0.0:9443"`、`quic_listen = "0.0.0.0:9443"`。
  - [ ] `client.toml` 使用 `server_addr = "quic://server:9443"` 或 compose service 名；`server_name` 与证书匹配。
  - [ ] 明确 `cert_path`/`key_path`/`policy_path`/`ca_cert_path` 都指向挂载目录内的文件。
- [ ] README 改为挂载完整配置目录：
  ```sh
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$PWD/examples/docker:/etc/uncrowned-king:ro" \
    -p 9443:9443/tcp -p 9443:9443/udp \
    uncrowned-king-server
  ```
  - [ ] 说明 `--user` 用于匹配宿主机 0600 文件；如果坚持镜像内 UID 65532，则必须 `chown 65532:65532`。
  - [ ] 说明不能把配置改成 0644 来绕过，二进制会拒绝。
- [ ] 新增 `examples/docker/docker-compose.yml`：
  - [ ] server + client 两个服务。
  - [ ] 配置目录只读挂载；客户端通过 compose 网络连 server。
  - [ ] 健康检查调用 `/healthz`、`/readyz`（需把 observability 绑定到容器可访问地址）。
- [ ] 在 README 中增加“为什么示例 server.toml 不能直接用于 Docker”的说明。
- [ ] 可选：提供 `--config-check` 的一次性容器命令，便于部署前验证。

**测试**

- [ ] CI 增加 Docker smoke：
  - [ ] `docker build --target server` / `--target client`。
  - [ ] 用临时证书/配置运行 server `config-check`。
  - [ ] 启动 server + client，执行一次 SOCKS 请求（curl 或 python）。
  - [ ] 验证容器内进程 UID 与文件权限。
- [ ] 在 Linux runner 上执行 README 的复制粘贴命令，确保不依赖 Docker Desktop 的 UID 映射。

**验收**

- [ ] README 的 Docker 命令在 Linux 上可直接运行。
- [ ] 不再需要把配置改成 0644。
- [ ] Docker 示例覆盖证书、私钥、策略、CA 和正确的监听地址。

---

## 2. P1：首个生产版本必须完成

### P1-1 Kubernetes staging 与 SIGHUP 轮换的一致性

**问题**

initContainer 把 Secret/ConfigMap 复制到 emptyDir，SIGHUP 读取副本；修改 Secret/ConfigMap 不会更新副本。外部 `existingTlsSecret`/`existingSecret` 没有 checksum，轮换不会触发 rollout。文档只在 standalone 清单中说明，Helm chart 没有同等提示。

**涉及文件**

- [deploy/helm/uncrowned-king/templates/server-deployment.yaml](../deploy/helm/uncrowned-king/templates/server-deployment.yaml:48)
- [deploy/helm/uncrowned-king/templates/client-daemonset.yaml](../deploy/helm/uncrowned-king/templates/client-daemonset.yaml:51)
- [docs/key-management.md](../docs/key-management.md:128)

**实现**

- [ ] 文档明确 Helm/Standalone 的 staging 语义：修改 Secret/ConfigMap 后必须 rollout restart，SIGHUP 不能感知。
- [ ] 为 `existingTlsSecret`/`existingSecret` 增加 checksum 注解（可用 Helm `lookup` 读取当前 Secret 内容并 sha256）；至少让 `helm upgrade` 触发 rollout。
- [ ] 或增加 config-reloader sidecar：
  - [ ] 监听挂载的 Secret/ConfigMap 变化；
  - [ ] 复制到 emptyDir；
  - [ ] 对主进程发送 SIGHUP；
  - [ ] 失败时保留旧副本并记录事件。
- [ ] 更新 `docs/key-management.md` 的 Kubernetes caveat，覆盖 Helm chart，而不只是 standalone manifest。
- [ ] 在 values/README 中说明证书/凭据轮换步骤。

**测试**

- [ ] `helm template` 断言：外部 Secret 场景生成 checksum 注解。
- [ ] 若实现 reloader：kind 集群中更新 Secret，验证新连接使用新证书/凭据，旧连接不断。
- [ ] 若仅文档方案：运行手册步骤演练通过（rollout restart 后新连接生效）。

**验收**

- [ ] 操作者不会误以为 SIGHUP 能在 K8s staging 下完成轮换。
- [ ] 证书/凭据轮换有明确、可执行的流程。

---

### P1-2 SETTINGS 协议一致性

**问题**

`docs/spec-v1.0.md` 要求 peers 发送 SETTINGS；实际只有服务端发送，客户端不发送，且服务端会把客户端 SETTINGS 当作 unexpected frame 关闭。第三方实现按规范发送会失败。

**涉及文件**

- [docs/spec-v1.0.md](../docs/spec-v1.0.md:278)
- [crates/uk-client/src/session.rs](../crates/uk-client/src/session.rs:573)
- [crates/uk-server/src/relay/session.rs](../crates/uk-server/src/relay/session.rs:556)

**实现（二选一，推荐 A）**

- [ ] **A. 实现双向 SETTINGS**
  - [ ] 客户端在认证后、进入 relay 前发送自己的 SETTINGS（包含 `protocol_revision`、`max_frame_size`、`max_streams`、`max_udp_flows`、能力位、idle timeout）。
  - [ ] 服务端在会话开始允许并校验客户端 SETTINGS；未知/重复/超限值按规范拒绝。
  - [ ] 明确顺序：服务端先发 SETTINGS，客户端读取后发送自己的 SETTINGS；服务端在进入 relay 前读取。
  - [ ] 服务端出站帧的大小/流数是否受客户端 SETTINGS 约束；至少校验并记录。
  - [ ] 更新 `docs/spec-v1.0.md`、`docs/architecture.md` 的时序图。
  - [ ] 增加“最小规范客户端”互操作测试。
- [ ] **B. 修订规范为 server-only**
  - [ ] 删除“Peers must send”表述，明确客户端能力目前放在 `AUTH_RESPONSE.client_capabilities`，SETTINGS 仅服务端发送。
  - [ ] 在协议版本说明中记录这是 1.0 的既定行为，而不是遗漏。
  - [ ] 仍然建议未来版本支持双向 SETTINGS。

**测试**

- [ ] 服务端接受/校验客户端 SETTINGS 的单元测试（如果选 A）。
- [ ] 客户端发送 SETTINGS 的帧顺序测试。
- [ ] 第三方/最小实现 e2e：按 spec 发送 SETTINGS 的客户端能完成握手和一次 TCP relay。
- [ ] 错误场景：客户端 SETTINGS 缺少 revision、重复 key、超限值 → 明确错误。

**验收**

- [ ] 规范与实现一致；多实现互操作测试通过，或有明确的版本说明。

---

### P1-3 策略域名规则与 Target 语法共用校验

**问题**

`Target::Domain` 只允许 `[A-Za-z0-9.-]`，但 policy 的 `is_unmatchable_domain_pattern` 只拒绝 `* / : @`、空白和 IP 字面量；`_` 等字符可通过 `config-check`，但永远匹配不到目标。若这是 deny 规则，会静默变成 no-op。

**涉及文件**

- [crates/uk-policy/src/lib.rs](../crates/uk-policy/src/lib.rs:441)
- [crates/uk-proto/src/target.rs](../crates/uk-proto/src/target.rs:184)

**实现**

- [ ] 提取共享 validator，例如 `uk_proto::validate_domain_pattern` 或 `Target::validate_domain_str`：
  - [ ] 支持 policy 需要的 leading dot（suffix）和 trailing dot（FQDN 归一化）。
  - [ ] 只允许 `[A-Za-z0-9-]` 和 `.`；拒绝 `_`、`+`、`~`、`/`、`:`、`@`、`*`、空白、控制字符、Unicode、IP 字面量。
  - [ ] 校验 label 长度 1..=63、总长 <=255、首尾 hyphen 规则。
- [ ] `validate_domain_match` 和 `validate_domain_suffix_match` 使用该 validator。
- [ ] 错误信息说明“该 pattern 永远不可能匹配 Target::Domain”。
- [ ] 评估是否允许 `_`：如果业务需要 `_service._tcp` 等，需要同时放宽 `Target::validate_domain` 和 policy；但必须确认 DNS/SOCKS 语义。

**测试**

- [ ] `domain = "foo_bar.com"`、`domain_suffix = ".corp_internal"` → `PolicySet::from_toml` 失败。
- [ ] `domain = "example.com"`、`domain_suffix = ".example.com"` → 通过。
- [ ] `domain_suffix = "example.com."`、`domain = "Example.COM"` → 通过并正确匹配。
- [ ] IP 字面量、URL、端口、通配符 → 失败。
- [ ] 回归：示例 policy 仍通过。

**验收**

- [ ] 任何通过 `config-check` 的 policy pattern 都能匹配至少一种合法 Target；不再有“silent no-op”规则。
- [ ] deny 规则不会因为字符集不一致而失效。

---

### P1-4 策略决策前移，消除 DNS oracle

**问题**

`connect_allowed_target_inner()` 先 `resolve_target()`，再 `PolicySet::evaluate()`。即使 deny-all，已认证客户端也能让服务端解析任意域名，并通过 `TargetUnavailable`（解析失败）vs `PolicyDenied`（解析成功）区分结果，形成内网 DNS 枚举/外带通道。

**涉及文件**

- [crates/uk-server/src/relay/dialer.rs](../crates/uk-server/src/relay/dialer.rs:45)
- [crates/uk-policy/src/lib.rs](../crates/uk-policy/src/lib.rs:87)

**实现**

- [ ] 增加 policy 的“域名预检”API：
  - [ ] 只使用 `Target::Domain`、`key_id`、`policy_group`、`port` 评估规则。
  - [ ] 如果没有任何 allow 规则可能匹配，或明确的 deny 域名规则匹配，直接返回 `PolicyDenied`，不解析 DNS。
  - [ ] 如果存在 allow 候选，再解析，并执行完整的 private/CIDR/metadata 检查。
- [ ] 确保 hard metadata deny 仍然在最终 IP 上执行。
- [ ] 统一错误响应/时序：对“域名被策略拒绝”和“解析失败但无 allow 候选”返回同一类错误，避免 oracle。
- [ ] 可选：对解析失败的域名做短期负缓存，减少 DNS 放大。
- [ ] 评估 DNS 解析本身的外带风险；必要时限制允许解析的域名集合。

**测试**

- [ ] deny-all + 可解析域名 → `PolicyDenied`，且 resolver 未被调用。
- [ ] deny-all + 不可解析域名 → 同样 `PolicyDenied`，不暴露解析失败。
- [ ] allow `domain_suffix` + 私有解析 → 解析后仍 deny（private 检查）。
- [ ] allow `cidr` + 公共解析 → 正常拨号。
- [ ] 使用 mock resolver/计数器断言 DNS 调用次数。

**验收**

- [ ] 被策略拒绝的目标不会触发 DNS 查询。
- [ ] 客户端无法通过错误码/时序枚举内网域名。

---

### P1-5 客户端 SIGTERM 时的上行排空

**问题**

`relay_tcp` 的 shutdown 分支只 `flush_buffered_frames_before_shutdown`（server→local），然后 `local.shutdown()`；本地 socket 中尚未读取的上传字节不会发送，且不发送 `TCP_CLOSE`。滚动更新可能截断上传。

**涉及文件**

- [crates/uk-client/src/relay/tcp.rs](../crates/uk-client/src/relay/tcp.rs:127)

**实现**

- [ ] 为每个 TCP flow 定义 shutdown drain deadline（例如共享 `shutdown_timeout_seconds` 预算）。
- [ ] shutdown 触发后：
  - [ ] 继续读取 local，发送 `TCP_DATA`，直到 local EOF 或 deadline。
  - [ ] 发送 `TCP_CLOSE(normal)`。
  - [ ] 继续排空 server→local 已排队帧。
  - [ ] 最后关闭 local socket。
- [ ] 如果 deadline 到达仍有未读数据，记录指标/日志（例如 `client.shutdown.upload_truncated`），不要静默丢弃。
- [ ] 确保该逻辑不会让 shutdown 无限等待：deadline 到期后 abort/关闭。
- [ ] 与 `drain_socks_tasks` 的 30s 预算协调，避免 2× timeout。

**测试**

- [ ] e2e：本地应用持续上传 1 MiB，目标慢读；发送 SIGTERM；断言目标收到完整数据（或在 deadline 内收到尽可能多，并记录截断指标）。
- [ ] e2e：本地应用不关闭，验证 deadline 后进程能退出。
- [ ] 单测：shutdown 期间 `TCP_CLOSE` 只发送一次；flow 正确移除。

**验收**

- [ ] 优雅关闭不再无条件丢弃本地已写入的上传尾部。
- [ ] shutdown 仍有硬上限。

---

### P1-6 UDP association 本地→服务器路径并发化

**问题**

`relay_udp_association` 主循环 `await handle_local_udp_datagram()`；打开新目标的 flow（最长 `tcp_open_timeout`）或 carrier 写入会阻塞整个 association，其他目标的 UDP 报文在 64 KiB socket 缓冲区排队/丢弃。

**涉及文件**

- [crates/uk-client/src/relay/udp.rs](../crates/uk-client/src/relay/udp.rs:196)

**实现（建议）**

- [ ] 将本地→服务器的发送路径从 association 主循环中拆出：
  - [ ] 主循环只负责 `recv_from`、SOCKS 头解码、来源校验、入队。
  - [ ] 每个 target 一个有界 mpsc 队列 + worker task（或一个共享 worker + 按 target 串行）。
  - [ ] worker 负责 `flow_for_target`、`send_udp_data`、失败重试/清理。
  - [ ] 队列满时按 UDP 语义丢弃并记录 `socks5.udp_association.queue_full`。
- [ ] 保持 `flows_by_target` 的所有权清晰：可以由 worker 持有，或通过事件回传主循环。
- [ ] 确保 worker 受 association shutdown 管理，`close()` 时 join/abort。
- [ ] 确保 `max_udp_flows`/permit 的释放仍然及时。

**测试**

- [ ] 一个慢目标（握手/写入慢）+ 一个快目标；快目标的报文不被慢目标阻塞。
- [ ] 队列满时丢弃新报文，不关闭 association。
- [ ] 关闭 association 时所有 worker 退出，流表和 permit 回收。
- [ ] 使用确定性同步，不用短 sleep。

**验收**

- [ ] 单个目标打开/发送慢不会导致整个 SOCKS UDP association 停顿。
- [ ] 内存仍由每 target/每 association 队列上限约束。

---

### P1-7 NetworkPolicy 最小权限（DNS 与客户端 egress）

**问题**

- Server/client 的 DNS egress 规则只有 `ports: 53`，没有 `to`；Kubernetes egress 规则是 OR，因此任意目的地 53 被允许，绕过 private/metadata 排除。
- 客户端 carrier egress 只限定端口 443/8443，没有限定 server；被攻陷的客户端可直连任意内网 443。
- 客户端 ingress 允许所有 namespace（见 P0-4）。

**涉及文件**

- [deploy/helm/uncrowned-king/templates/network-policy.yaml](../deploy/helm/uncrowned-king/templates/network-policy.yaml:100)
- `deploy/kubernetes/*.yaml`

**实现**

- [ ] 增加可配置的 cluster DNS 目标：
  - [ ] `networkPolicy.dns.namespaceSelector`（例如 `kube-system`）或 `dns.cidrs`。
  - [ ] DNS 规则加 `to`，只允许到 cluster DNS。
  - [ ] 如果需要外部 DNS，单独显式配置，不要默认任意 53。
- [ ] 客户端 egress 加 `to`：
  - [ ] server namespace + pod selector（`app.kubernetes.io/component: server`）。
  - [ ] 只允许 server Service 端口/targetPort。
- [ ] 客户端 ingress 加 namespace/pod 白名单（与 P0-4 一起）。
- [ ] 验证 NetworkPolicy 不产生 `from: []`/`to: []` 黑洞语法。
- [ ] 更新 `values.yaml` 和 README 的网络策略示例。

**测试**

- [ ] `helm template` 断言 DNS/egress 规则包含 `to`。
- [ ] kind 集群：从客户端 Pod 访问非 server 的 443 应失败；访问 server 应成功。
- [ ] kind 集群：DNS 解析仍正常；访问非 DNS 的 53 应失败。
- [ ] kubeconform/kube-linter（如已使用）通过。

**验收**

- [ ] NetworkPolicy 真正实现“只允许 DNS + UK server”，而不是“任意 53/443”。
- [ ] 不影响 kubelet 探针和正常 DNS。

---

### P1-8 Helm 顶层配置白名单与渲染后 config-check

**问题**

`server-configmap.yaml` 只对 `limits` 做白名单；顶层 `quic_lisen` 等拼写错误被静默忽略。实测：

```sh
helm template ... --set server.config.quic_lisen=0.0.0.0:9999
# 渲染仍是 quic_listen = "0.0.0.0:8443"
```

CI 的 helm job 只做 lint/template，不执行二进制 `config-check`，无法发现配置语义错误。

**涉及文件**

- [deploy/helm/uncrowned-king/templates/server-configmap.yaml](../deploy/helm/uncrowned-king/templates/server-configmap.yaml:9)
- [.github/workflows/ci.yml](../.github/workflows/ci.yml:52)

**实现**

- [ ] 在 server-configmap 中定义 `knownServerFields`：
  - [ ] `listen`
  - [ ] `quic_listen`
  - [ ] `observability_listen`
  - [ ] `auth_skew_seconds`
  - [ ] `log_format`
  - [ ] `limits`
  - [ ] 其他真正支持的字段
- [ ] 对未知顶层字段 `fail`，错误信息包含字段名。
- [ ] 对 client 已有白名单做一次对齐检查（确保 `key_id`/`secret` 的特殊处理仍正确）。
- [ ] CI 增加：
  - [ ] `helm template` 渲染 server/client TOML。
  - [ ] 用临时证书/密钥/策略，执行 `uk-server config-check`、`uk-client config-check`。
  - [ ] 断言一个已知拼写错误会让 `helm template` 失败。
- [ ] 可选：用 `helm unittest` 或 shell 断言测试，固定输出。

**测试**

- [ ] `--set server.config.quic_lisen=...` → helm 失败。
- [ ] 合法 values → 渲染 + config-check 通过。
- [ ] client 未知字段 → 失败（防止回归）。
- [ ] `server.config.limits` 超限值 → config-check 失败（与 P0-2 联动）。

**验收**

- [ ] Helm values 拼写错误不会静默降级。
- [ ] CI 能在合并前发现“渲染成功但二进制启动失败”的配置。

---

## 3. P2：按迭代排期

> 以下任务建议在 P0/P1 完成后按影响排序；每项仍需独立测试。

### P2-1 UDP 大报文支持（默认 16 KiB 限制）

- [ ] 明确 `data_frame_size = min(max_frame_size, relay_buffer_size)` 对 UDP 的影响。
- [ ] 方案 A：为 UDP 单独使用 `max_frame_size`（仍然受 per-flow/session 字节预算约束）。
- [ ] 方案 B：文档化默认 16 KiB 限制，建议需要大 UDP 的部署调大 `relay_buffer_size`，并说明两端需匹配。
- [ ] 测试：20 KiB / 32 KiB / 64 KiB UDP 报文的发送、回退、丢弃日志。
- [ ] 与 QUIC DATAGRAM 的 max size 行为对齐；不要产生“静默截断”。

### P2-2 修复 reload 与 degraded endpoint 的竞态

- [ ] `DEGRADED_ENDPOINTS` 绑定 config generation，或在 `mark_endpoint_degraded` 前检查当前 generation。
- [ ] reload 清理 degraded 状态后，旧 generation 的 in-flight connect 不得再写入。
- [ ] 测试：启动一个慢 connect → reload → 旧 connect 超时 → 新 generation 不应看到 degraded 标记。
- [ ] 保留 180s 冷却和成功清除逻辑。

### P2-3 客户端 ServiceMonitor / metrics Service

- [ ] Helm 增加可选 client Service（与 P0-4 配套）。
- [ ] 增加可选 client ServiceMonitor（`serviceMonitor.client.enabled`），选择 client metrics Service/端口。
- [ ] 测试：`helm template` 渲染；Prometheus Operator 可发现。
- [ ] 如果客户端只作为 sidecar，明确不需要 Service/Monitor，并在 values 中默认关闭。

### P2-4 systemd `LimitNOFILE` 与容量对齐

- [ ] 将 server/client unit 的 `LimitNOFILE` 提高到至少 `2 × max_sessions × max_streams` 的推荐值（例如 1,048,576）。
- [ ] 或在 `docs/operations.md` 中要求按实际配置覆盖，并增加启动检查/日志。
- [ ] `TasksMax` 评估（Tokio 线程 + 阻塞池）。
- [ ] 测试：高并发流下不出现 `EMFILE`；unit 的 `systemd-analyze verify` 通过。

### P2-5 认证限流的 NAT / IPv6 误伤

- [ ] 文档说明默认 5 次/60s、IPv6 /64 聚合、NAT 共享 IP 的风险。
- [ ] 增加 `auth_rate_limit_allowlist`（IP/CIDR）或按 `key_id` 维度限流。
- [ ] 评估是否提高默认阈值或缩短 ban 时间；保持防爆破能力。
- [ ] 测试：共享 NAT 场景一个 IP 的失败不影响白名单；IPv6 /64 内不同地址的行为符合文档。

### P2-6 元数据硬封禁补齐 ECS 等端点

- [ ] 将 AWS ECS 任务元数据 `169.254.170.2` 加入 `is_metadata_service_ip` 的永久拒绝。
- [ ] 评估是否增加可配置的额外 metadata CIDR（避免每次云厂商新增地址都改代码）。
- [ ] 测试：`Target::Ipv4(169.254.170.2)`、域名解析到该地址、`private=true` allow 规则下仍 deny。
- [ ] 更新 `docs/threat-model.md` 和 AGENTS 的列表（如适用）。

### P2-7 客户端 SOCKS 监听的双栈可配置

- [ ] Helm/standalone/Docker 不要写死 `0.0.0.0`；增加 `listen` values。
- [ ] 文档说明 IPv6-only 集群使用 `[::]:1080`（并验证双栈行为）。
- [ ] 测试：IPv6-only kind 集群或本地 `[::1]` 监听。
- [ ] 保持非 loopback 需要显式 `--allow-non-loopback` 的安全语义。

### P2-8 `/metrics` HEAD 语义

- [ ] `HEAD /metrics` 返回与 GET 相同的 `Content-Length`（计算 metrics 长度，或内部渲染后丢弃 body）。
- [ ] 测试：HEAD 与 GET 的 header 一致；body 为空。
- [ ] 保持 `/healthz`、`/readyz` 的 HEAD 行为。

### P2-9 半关闭超时发送 `TCP_CLOSE`

- [ ] `handle_half_close_drain_expired` 的 `Abort` 分支在移除 flow 前发送 `TCP_CLOSE(error)`。
- [ ] 确保发送失败不会阻止 flow 清理。
- [ ] 测试：目标先关闭、客户端不关闭、超时后客户端收到 close。
- [ ] 检查 UDP 对应路径是否需要类似处理。

### P2-10 指标文案与文档一致性

- [ ] `accepted_connections_total` 的 HELP 改为“Accepted TCP and QUIC carrier connections”，或增加 `carrier` label。
- [ ] 修正 `docs/architecture.md` 的 ALPN 为 `uk/1`。
- [ ] 检查 AGENTS 的证书权限要求与代码的“只检查私钥”差异；更新 AGENTS 或代码，二者选一。
- [ ] 更新 README 的“v0.1 milestone”描述与 1.0.2 现状。
- [ ] 为 `docs/spec-v1.0.md` 的 SETTINGS 方向（取决于 P1-2）加注。

### P2-11 客户端 CA 加载 / reload 的阻塞超时

- [ ] `tls::shared_client_config` 的 `spawn_blocking` 外层增加超时（可用 `handshake_timeout_seconds` 或专用配置加载超时）。
- [ ] `ClientSessionManager::reload` 中的 `check_config`/`refresh_client_config` 增加超时，避免慢文件系统阻塞 listener accept loop。
- [ ] 服务端 `apply_security_reload` 的证书/密钥加载同样增加超时或至少在文档中说明。
- [ ] 测试：用可控的慢阻塞任务模拟，验证超时返回错误且旧配置保持不变。
- [ ] 确保超时后不会发布部分新状态（CA 缓存、generation）。

### P2-12 Docker / K8s / Helm CI smoke

- [ ] CI 增加 Docker build + run + SOCKS 请求。
- [ ] CI 增加 Helm 渲染 + 二进制 config-check。
- [ ] CI 增加客户端 `/readyz` 冷启动/空闲测试（可用本地进程，不必 K8s）。
- [ ] 可选：kind 集群 e2e，验证 Service/NetworkPolicy/rollout。
- [ ] 将上述测试加入 release gate，而不是只在 PR 上跑。

---

## 4. 建议的实施波次

### Wave 1（阻断项，建议 1 个 PR 或少量 PR）

- [ ] P0-1 客户端 readiness/maintainer
- [ ] P0-2 server 配置上限
- [ ] P0-3 全局资源预算 + Helm sizing
- [ ] P0-4 K8s 客户端网络/Service
- [ ] P0-5 Docker 文档与示例

### Wave 2（生产加固）

- [ ] P1-1 staging/轮换
- [ ] P1-2 SETTINGS
- [ ] P1-3 policy 域名校验
- [ ] P1-4 DNS 预检
- [ ] P1-5 客户端上行排空
- [ ] P1-6 UDP association 并发
- [ ] P1-7 NetworkPolicy 最小权限
- [ ] P1-8 Helm 白名单 + CI config-check

### Wave 3（质量与边界）

- [ ] P2-1 ～ P2-12 按影响排序
- [ ] 更新 dashboard/alerts/runbook
- [ ] 做一次完整 soak + chaos + 滚动更新演练

---

## 5. 最终发布 checklist

### 功能与协议

- [ ] TCP/UDP over TLS/TCP 与 QUIC 全部 e2e 通过。
- [ ] QUIC DATAGRAM / UDP_DATA fallback 通过。
- [ ] SETTINGS 协商与第三方 interop 通过（或文档明确 server-only）。
- [ ] SIGHUP 在裸机/systemd 下轮换 TLS/凭据/策略通过。
- [ ] K8s staging 下的轮换流程演练通过（rollout/reloader）。

### 可用性

- [ ] 客户端无流量冷启动 `/readyz` 200。
- [ ] 空闲 > server idle timeout 后 `/readyz` 自愈。
- [ ] server 重启后 client 自动恢复。
- [ ] K8s Deployment 滚动更新完成，Service Endpoints 不空窗。
- [ ] 客户端 SIGTERM 后上传数据不静默截断（或明确记录截断指标）。

### 安全

- [ ] 策略 deny 规则不存在“永远不匹配”的 pattern。
- [ ] 被拒绝目标不触发 DNS 解析。
- [ ] 云 metadata（含 ECS）在 `private=true` 下仍被硬拒绝。
- [ ] K8s 客户端默认不暴露给所有 namespace，egress 只到 server/DNS。
- [ ] Docker 配置/密钥权限正确，无 0644 绕过。
- [ ] 证书/凭据轮换不依赖失效的 SIGHUP 假设。

### 容量与运维

- [ ] `max_sessions × max_buffered` 与 memory limit 匹配。
- [ ] `LimitNOFILE` 与 `max_sessions × max_streams` 匹配。
- [ ] soak 下 RSS/FD 稳定，资源耗尽返回 `RESOURCE_LIMIT` 而非 OOM。
- [ ] `/metrics` 与告警/dashboard 一致；新增指标有 HELP/TYPE。
- [ ] Docker/Helm/systemd 安装路径均完成一次真实演练。

### 发布卫生

- [ ] 版本号在 Cargo.toml/Cargo.lock/Chart/values/manifests/CHANGELOG 同步。
- [ ] CI 全绿：fmt/check/test/clippy/doc/deny/audit/fuzz smoke/helm config-check/Docker smoke。
- [ ] 回滚方案演练：上一版本二进制 + 配置。
- [ ] 风险接受记录：任何未修的 P1/P2 都有 owner、期限和补偿措施。
