# Uncrowned King 潜在缺陷与生产就绪审查报告

审查日期：2026-09-09（Asia/Taipei）  
审查版本：工作区 v0.1.3，HEAD `81623b5219c758ba4a2c99bb5a29b3fb1137ac42`，包含审查开始前已有的未提交修改。

## 1. 上线判断

**当前版本不建议直接投入正式生产，尤其不应直接开放公网 QUIC 或使用现有 Helm 默认配置部署。** 建议定位为修复中的候选版本，先完成下述阻断项，再进入受控预生产环境。

这不是因为项目缺少基础实现。认证、协议解析、常规转发、重连退避和大量测试已有较好基础；但审查发现了队列数据在优雅关闭中被丢弃、QUIC 认证前传输缓冲边界缺失、Helm 无法启动，以及客户端异常清理和重载状态不一致等实际问题。测试通过不足以覆盖这些调度交错和部署路径。

本报告列出 **12 项发现：5 项 P1、7 项 P2**。严重度表示修复优先级；每项另行注明触发条件和证据强度。未确认 P0 级认证绕过或远程代码执行，不代表已证明不存在其他漏洞。

| 使用场景 | 判断 | 原因 |
| --- | --- | --- |
| 公网正式服务，开启 QUIC | 暂不批准 | F01 的认证前资源风险，另有 F02 数据完整性问题 |
| 直接使用现有 Helm Chart | 暂不批准 | F03、F04 使部署无法正常启动；启用客户端还存在 F05 |
| 仅 TLS/TCP 的正式生产 | 暂不批准 | 关闭 QUIC 无法解决 F02 以及客户端生命周期问题 |
| 隔离的开发、功能验证环境 | 可以继续 | 需使用合成凭据、限制访问范围；结果不等于生产容量或可用性承诺 |
| 修复后的预生产灰度 | 有条件允许 | 必须先满足第 6 节的验收门槛 |

## 2. 范围与验证结果

覆盖五个 Rust crate 的核心路径，重点检查 `uk-auth`、`uk-policy`、`uk-proto`、客户端与服务端 relay、SIGHUP、SOCKS、QUIC、容器/Helm/Kubernetes、CI 和运维文档。进行了源码审查、实际命令验证和隔离副本中的定向回归测试。

原工作区已有修改：`PRODUCTION_READINESS_REPORT.md`、`crates/uk-client/tests/tcp_relay_e2e.rs`、`crates/uk-server/src/relay/tasks.rs`、`crates/uk-server/src/relay/tests.rs`、`crates/uk-server/tests/adversarial_sec_challenge.rs`。本次保留这些修改，没有修改生产源码或应用复现补丁。新增内容只有本报告和 `docs/audits/2026-09-09/` 中的证据文件。

运行环境：macOS / Apple Silicon，Rust 1.96.1；另使用 Rust 1.85.0 检查最低支持版本。Helm 使用临时下载、SHA-256 校验匹配的 3.18.6。没有 Docker、kubectl 或实际 Kubernetes 集群，因此容器所有权与网络暴露结论来自渲染结果及运行用户配置，未宣称完成集群实测。

| 验证项目 | 结果 | 解释 |
| --- | --- | --- |
| `cargo test --workspace --locked -q` | **850 通过，0 失败，3 忽略** | 包括 103 个 TCP/UDP/QUIC 等端到端测试、18 个对抗测试；忽略项为手动性能/持续运行测试 |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 通过 | 当前工作区 |
| `cargo +1.85.0 check --workspace --locked` | 通过 | MSRV 编译检查；未完整重跑该版本全部测试 |
| `cargo build --workspace --release --locked` | 通过 | 当前 macOS 架构；未构建 Linux 容器 |
| `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked` | 通过 | 文档编译 |
| `cargo fmt --all --check` | **失败** | 已有未提交文件 `adversarial_sec_challenge.rs:1271` 附近格式不符；不是运行时缺陷，但会阻断 CI |
| `cargo audit --json` | 通过，0 已知漏洞 | 176 个依赖；RustSec 数据库 1,243 条公告，提交 `b50980aad8b8f14f77e25a97b32dd94bf008b0af`，更新时间 2026-09-09；不覆盖本项目逻辑漏洞 |
| `cargo deny check` | 通过 | advisories、bans、licenses、sources 均通过；有重复 `windows-sys` 警告 |
| Helm lint / template | lint 通过、渲染成功 | 提供合成 existingSecret/existingTlsSecret 名称后执行；lint 不验证内嵌 TOML，也不验证文件所有权 |
| 渲染后的服务端 `config-check` | **失败** | 依次确认浮点格式、过大缓冲上限、未知策略字段三个独立问题，见 F03 |
| `env NO_PROXY= no_proxy= ./scripts/interop-curl.sh` | **失败，exit 97** | TLS 阶段 SOCKS 连接失败，未到 QUIC；见 F12 |
| release 模式 60 秒 soak/chaos | 通过 | 16 个 flow，3,702,625 次往返、1,176 次拒绝流注入；仅本机短时验证，不是 24 小时耐久或公网性能测试 |
| 本次新增的隔离回归测试 | 多项失败，证明漏测缺陷 | 断言表达正确行为，失败结果是审查证据；这些测试未加入当前项目测试集 |

常规检查日志：[证据目录说明](</Users/lesliealexander/Uncrowned King/docs/audits/2026-09-09/evidence/README.md>)。客户端与服务端的复现补丁只添加审查测试，可在副本应用；不要把新增复现测试的预期失败与原测试集的通过结果混为一谈。

## 3. 发现摘要

| ID | 级别 | 问题 | 证据 |
| --- | --- | --- | --- |
| F01 | P1 | QUIC 接受协议不使用的远端流，认证前缓冲未受 UK 帧限制约束 | 项目与锁定依赖源码；未完成主动复现 |
| F02 | P1 | 双向半关闭与停机交错时，优雅关闭丢弃已排队数据 | 完整 relay_session + 真实 TCP 目标复现 |
| F03 | P1 | Helm 生成的 TOML 无法通过启动校验 | Helm 实际渲染 + 二进制 config-check |
| F04 | P1 | Helm initContainer 生成 root:root 0600 文件，主进程不可读 | 模板与镜像运行用户静态核对 |
| F05 | P1 | 启用 Helm 客户端会把无认证 SOCKS 暴露到节点端口 | 实际渲染 + Kubernetes 网络语义 |
| F06 | P2 | 被拒绝的客户端 reload 仍替换 TLS 信任缓存 | 隔离缓存状态复现 |
| F07 | P2 | SOCKS UDP 控制连接 RST 绕过流清理 | 真实本机 TCP RST + 内存 carrier |
| F08 | P2 | 旧 UDP 任务完成事件误删新会话的同 ID 流 | 确定性事件交错复现 |
| F09 | P2 | 已结束流的半关闭定时器继续存活 | 隔离组件复现 |
| F10 | P2 | Helm 没有输出 quic_listen，QUIC Service 没有对应监听器 | 实际渲染 |
| F11 | P2 | 部署镜像标签与发布工作流不一致，Helm 仍指向旧版本 | 仓库配置交叉检查 |
| F12 | P2 | 官方 curl 互通脚本被自身策略拒绝，不能完成验证 | 原脚本实际运行失败 |

### F01 · P1：QUIC 认证前传输缓冲缺少协议专用限制

位置：[quic.rs:69](</Users/lesliealexander/Uncrowned King/crates/uk-server/src/quic.rs:69>)、[quic.rs:136](</Users/lesliealexander/Uncrowned King/crates/uk-server/src/quic.rs:136>)。

服务端直接采用 `QuinnServerConfig::with_crypto` 的默认 TransportConfig。UK 只使用服务端自己打开的一条双向控制流，却没有将对端可新建的双向/单向流数量设为零，也不消费这些额外流。

锁定的 `quinn-proto 0.11.16` 默认允许 100 条入站双向流与 100 条入站单向流，每流接收窗口为 1,250,000 字节，连接总接收窗口为 `VarInt::MAX`。据此推断，仅这些额外流的传输层数据窗口就达到约 **250 MB/连接**，远大于默认 `max_pre_auth_bytes=4096`。这不是实测 RSS，也不意味着建立连接时立即分配全部内存；它表示协议允许对端逐步占用的缓冲量级。

触发需要能访问 QUIC 端口并完成 TLS/QUIC 握手，**不需要通过 UK HMAC 认证**。认证超时限制持续时间，却不能保证该时间窗口内的内存占用安全；多个连接会扩大影响。

建议：拒绝所有协议不使用的远端发起流，为控制流、连接接收窗口和 DATAGRAM 缓冲设置明确预算，并把它们计入未认证连接总内存预算。验证修复时应检查握手前后的 transport parameters、单连接和多连接的有界占用。

**验证限制：主动复现被工具自动安全审查拦截；此项按源码证据判为高置信资源风险，没有声称实测 OOM、远程攻击成功或 2 MiB 写入成功。** 锁定依赖参数与依据记录在证据目录。

### F02 · P1：优雅关闭可能丢弃 TCP 队列尾部数据

位置：[context.rs:739](</Users/lesliealexander/Uncrowned King/crates/uk-server/src/relay/context.rs:739>)、[tcp.rs:301](</Users/lesliealexander/Uncrowned King/crates/uk-server/src/relay/tcp.rs:301>)、[session.rs:135](</Users/lesliealexander/Uncrowned King/crates/uk-server/src/relay/session.rs:135>)、[session.rs:267](</Users/lesliealexander/Uncrowned King/crates/uk-server/src/relay/session.rs:267>)。

当目标已经关闭发送方向，客户端又发来正常 TCP_CLOSE 时，服务端在目标 writer 尚未写完队列前，就把两方向视为关闭并移除 flow。若此时正在停机 drain，主循环看见 flow 表为空，会调用 `shutdown.close()`；writer 随即取消仍待写的数据。

先用组件测试确认排队 18 字节全部丢失，随后在**完整 relay_session** 中进一步复现：使用默认 64 KiB frame、2 MiB flow buffer、30 秒 drain，目标先关闭发送方向，客户端在 drain 中上传 **1 MiB** 后正常 CLOSE。目标仅延迟读取 50 ms，服务端返回 `Ok(())`，目标却收到 **0 / 1,048,576 字节**；三次运行一致。该验证使用真实 TCP 目标，以内存 duplex 代替已经认证的 carrier，未覆盖 TLS/QUIC 握手，也不意味着所有正常停机都会丢数据。

建议：区分“收到半关闭请求”和“writer 已把队列写完并完成 shutdown”；只有收到 writer 完成事件、两方向都实际终止后才能释放 flow。正常 drain 与超时强制取消应分开处理。验收至少包含大载荷、慢目标、队列满、双向半关闭与 SIGTERM 的交错，并逐字节校验目标数据。

### F03 · P1：Helm 渲染结果存在连续的启动阻断点

位置：[server-configmap.yaml:24](</Users/lesliealexander/Uncrowned King/deploy/helm/uncrowned-king/templates/server-configmap.yaml:24>)、[values.yaml:66](</Users/lesliealexander/Uncrowned King/deploy/helm/uncrowned-king/values.yaml:66>)、[server-configmap.yaml:32](</Users/lesliealexander/Uncrowned King/deploy/helm/uncrowned-king/templates/server-configmap.yaml:32>)。

使用真实 Helm 渲染，在提供合成凭据/TLS Secret 名称后确认：

1. 默认整数缓冲值被输出成 `6.7108864e+07`、`4.194304e+06`，TOML 将其识别为浮点数，Rust `u64` 反序列化失败。
2. 只纠正整数输出后，64 MiB 的 `max_buffered_bytes_per_session` 仍超过程序 16 MiB 硬上限，`config-check` 报 `must be at most 16777216`。
3. 再修正上限并提供有效测试证书后，策略必定包含 `default_action = "deny"`；`RawPolicySet` 使用 `deny_unknown_fields` 且只接受 `rules`，因此继续报 `unknown field default_action`。

此外，策略模板只序列化部分规则字段，遗漏 `domain_suffix`、`private`、`key_id`。当前配置先被上述错误阻止启动；若只修启动错误，域后缀白名单可能因条件被丢弃而扩大匹配范围，`deny private=true` 也会变成不带该限制的拒绝规则。应一起修正序列化完整性，不能只删掉报错字段。

建议：显式输出十进制整数、让 values 与 Rust 限制保持一致、按真实 schema 生成策略；把“helm template → 提取最终拼接 TOML → client/server config-check → 策略正反例”加入 CI。证据：[config-check.log](</Users/lesliealexander/Uncrowned King/docs/audits/2026-09-09/evidence/deployment/config-check.log>)；[复现脚本](</Users/lesliealexander/Uncrowned King/docs/audits/2026-09-09/evidence/deployment/reproduce.py>)。

### F04 · P1：Helm 配置 staging 的所有权不匹配

位置：[server-deployment.yaml:30](</Users/lesliealexander/Uncrowned King/deploy/helm/uncrowned-king/templates/server-deployment.yaml:30>)、[client-daemonset.yaml:27](</Users/lesliealexander/Uncrowned King/deploy/helm/uncrowned-king/templates/client-daemonset.yaml:27>)、[Dockerfile:23](</Users/lesliealexander/Uncrowned King/Dockerfile:23>)。

两个 Helm workload 没有 Pod 级 `runAsUser/runAsGroup/fsGroup`。busybox initContainer 按默认 root 身份创建配置并 chmod 0600；主容器镜像却以 nonroot（65532）运行，也没有 chown 或统一运行 UID。文件因此归 root 所有且仅 root 可读，即使 F03 修好仍会因权限失败而无法启动。

手写 Kubernetes manifest 已有统一 UID/fsGroup，问题集中在 Helm 模板。建议让 init 与主进程采用同一非 root UID，并用 fsGroup 读取投射 Secret、写入共享 emptyDir；不要把文件改成 0644 绕过安全限制。部署后需以实际主容器 UID 验证读权限和 `config-check`。依据：[Kubernetes security context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)。本次未运行真实容器 UID 验证。

### F05 · P1：启用 Helm 客户端会默认开放节点 SOCKS 端口

位置：[client-daemonset.yaml:67](</Users/lesliealexander/Uncrowned King/deploy/helm/uncrowned-king/templates/client-daemonset.yaml:67>)、[values.yaml:109](</Users/lesliealexander/Uncrowned King/deploy/helm/uncrowned-king/values.yaml:109>)。

`client.enabled=true` 后，模板固定使用 `--listen 0.0.0.0:1080 --allow-non-loopback` 并设置 `hostPort:1080`，没有指定 hostIP，也没有附带访问控制。SOCKS 不要求认证，能到达该节点端口的主体就可能借用客户端凭据使用代理。服务端目标策略仍然有效，本问题不等于任意目标绕过。

客户端默认 disabled，因此未启用它的部署不受此项影响；而启用后的实际外部可达性取决于节点防火墙和网络。Kubernetes 未指定 hostIP 的 hostPort 默认为全部地址，参见[官方配置建议](https://kubernetes.io/blog/2025/11/25/configuration-good-practices/)。

建议默认取消 hostPort；确实需要节点入口时，明确绑定管理地址并验证节点级访问控制。不要把安装 DaemonSet 自动等同于同意提供无认证网络代理。验收需从非授权网络确认 1080 不可达，并从授权路径验证 SOCKS 功能。

### F06 · P2：reload 返回拒绝后，客户端 TLS 信任根仍会改变

位置：[session_manager.rs:185](</Users/lesliealexander/Uncrowned King/crates/uk-client/src/relay/session_manager.rs:185>)、[tls.rs:64](</Users/lesliealexander/Uncrowned King/crates/uk-client/src/tls.rs:64>)。

reload 先执行 `check_config`，该调用会覆盖按 CA 路径缓存的 TLS 配置，之后才检查需要重启的字段是否变化。原地替换 CA 并同时修改 `max_socks_connections` 时，reload 被拒绝、generation 仍为 1，但缓存已经换成新 CA；后续新 carrier 使用的信任状态与拒绝结果不一致。

复现结果：`generation=1, CA cache same=false`。这是缓存状态验证，未额外执行新 TLS 握手；既有 TLS 连接未被证明受影响。

建议让候选验证没有共享状态副作用，把 CA/TLS 对象包含在版本化配置快照中，全部检查通过后原子发布。验收要求失败 reload 前后缓存和新握手信任行为完全一致，成功 reload 才改变新连接信任根。

### F07 · P2：UDP ASSOCIATE 异常退出会跳过 cleanup

位置：[udp.rs:196](</Users/lesliealexander/Uncrowned King/crates/uk-client/src/relay/udp.rs:196>)、[udp.rs:214](</Users/lesliealexander/Uncrowned King/crates/uk-client/src/relay/udp.rs:214>)、[udp.rs:236](</Users/lesliealexander/Uncrowned King/crates/uk-client/src/relay/udp.rs:236>)。

控制 TCP 的 `read?` 或处理 datagram 的 `.await?` 出错会直接返回，绕过 `association.close()`。任务取消只释放 admission/metrics，不能完成 route 移除和服务端 UDP_CLOSE 通知。

真实 loopback 控制连接 RST、配合内存 carrier 的复现输出：`routes retained=1, available_udp_permits=8`。即 permit 已归还，route 却留存；服务端 socket 的后续回收依赖 idle timeout/会话关闭。频繁异常断开可能让容量记账分裂并逐渐影响后续 UDP 开流。

建议采用统一异步退出清理，错误返回也必须执行；验收覆盖 RST、写错误、重连失败和正常 EOF，检查两端 flow、permit、buffer、socket 最终一致回收。

### F08 · P2：UDP 旧任务可误删重连后的新 flow

位置：[udp.rs:470](</Users/lesliealexander/Uncrowned King/crates/uk-client/src/relay/udp.rs:470>)、[udp.rs:487](</Users/lesliealexander/Uncrowned King/crates/uk-client/src/relay/udp.rs:487>)、[session_manager.rs:727](</Users/lesliealexander/Uncrowned King/crates/uk-client/src/relay/session_manager.rs:727>)。

每条 carrier 都从 flow ID 1 分配，而 association 的完成事件只用 `(target, flow_id)` 匹配。旧 carrier 失败后重试可能先创建新 carrier 的同 target、同 ID 流，再处理旧任务完成通知；旧通知便删除了新映射。Activity 事件也缺少 session identity。

确定性复现创建两个独立 session，均分配 ID 1，随后投递旧任务完成结果，新 flow 映射确实消失。其后可能反复开流、改变目标侧 UDP socket、增加资源滞留；没有声称复现跨用户数据泄露。

建议事件与映射携带唯一 session identity/flow token，按 `(session identity, flow_id)` 校验。验收使用延迟旧 completion/activity 的重连测试，确认新流不被删除或误更新。

### F09 · P2：流完成后半关闭定时器未取消

位置：[tasks.rs:434](</Users/lesliealexander/Uncrowned King/crates/uk-server/src/relay/tasks.rs:434>)。

半关闭定时器只等待 timeout 或 session shutdown，不监听对应 flow 的完成。即使两方向都关闭并释放 flow 槽位，定时任务仍存活到默认 30 秒到期。

复现设置 `max_streams=1`，顺序完成 100 个 flow 后，flow 表为空而任务集合中仍有 **100 个定时器**。它们最终会到期，本报告不称其为永久泄漏；但数量随短连接周转率和 timeout 增长，突破“并发流上限即可约束后台任务数”的容量假设。

建议使用 per-flow 取消句柄或统一 deadline 容器，流终结立即删除定时项。验收在固定 max_streams 下持续周转，确认后台任务/定时器数量与存活流数量同阶，内存回到稳定基线。

### F10 · P2：Helm 的 QUIC Service 与配置脱节

位置：[server-configmap.yaml:10](</Users/lesliealexander/Uncrowned King/deploy/helm/uncrowned-king/templates/server-configmap.yaml:10>)、[server-service.yaml:23](</Users/lesliealexander/Uncrowned King/deploy/helm/uncrowned-king/templates/server-service.yaml:23>)。

Chart 暴露 UDP Service/containerPort，但生成的 `server.toml` 从不包含 `quic_listen`。实际设置 `--set server.config.quic_listen=0.0.0.0:8443` 后渲染结果仍无此项，因此服务端只启动 TLS/TCP，QUIC 连接超时并可能回退。

建议提供明确的 QUIC enable/listen 配置，并同步渲染 listener、Service 与端口。验收必须通过真实 QUIC 握手与转发确认，而不能只看 Service 存在或 `/readyz` 成功。

### F11 · P2：发布标签与部署引用不一致

位置：[release.yml:123](</Users/lesliealexander/Uncrowned King/.github/workflows/release.yml:123>)、[values.yaml:16](</Users/lesliealexander/Uncrowned King/deploy/helm/uncrowned-king/values.yaml:16>)、[Kubernetes manifest:145](</Users/lesliealexander/Uncrowned King/deploy/kubernetes/uncrowned-king-server.yaml:145>)。

发布流程由 `vX.Y.Z` 标签触发，镜像使用完整 `github.ref_name`，因此生成 `v0.1.3` 和 latest。手写清单却引用 `:0.1.3`，Helm 引用 `:0.1.2`，Chart appVersion 也停留在 0.1.2。

若仅使用该仓库工作流产生的镜像，这些无 v 标签不会由该流程创建，可能导致拉取失败；若仓库外另有同名别名，则还需确认其实际内容。本次没有远程验证 registry 标签，故不声称这些标签目前必定不存在。Helm 版本落后也使本次 v0.1.3 审查结论不能用于为其镜像背书。

建议统一版本来源并最终按经过签名验证的 digest 部署，在发布验证中解析清单镜像、校验实际二进制版本。不要依赖 latest 或手工别名掩盖版本漂移。

### F12 · P2：curl 互通脚本与安全策略不兼容

位置：[interop-curl.sh:87](</Users/lesliealexander/Uncrowned King/scripts/interop-curl.sh:87>)。

脚本创建允许 `127.0.0.1/32` 的规则，却没有按当前安全策略显式设置 `private=true`。默认拒绝私网的行为正确，因此脚本自身的本机 HTTP 目标被拒绝。

清空 NO_PROXY/no_proxy 后执行原脚本，在 TLS/TCP 阶段得到 `curl: (97) Can't complete SOCKS5 connection`，QUIC 测试未执行。清空变量是为了确保请求实际通过 SOCKS，避免环境代理排除项产生假通过。

建议仅对脚本生成的精确 loopback/端口测试规则显式允许 private，强制该请求经过 SOCKS，并在 CI 跑两个 carrier。此项是验证工具缺陷，不应通过弱化生产策略默认值解决。

## 4. 已确认的安全基础与尚未证明的风险

本次没有把以下已修正项重复列为漏洞：

- 五个 crate 均继承工作区 `unsafe_code=forbid`；源码与编译检查未发现新 unsafe 代码。
- Key ID 查找使用固定长度缓冲的 `ConstantTimeEq`，未知 key 执行 dummy HMAC；验证 MAC 后再处理时钟/凭据状态。测试不构成对所有硬件微架构的完整侧信道证明。
- 协议拒绝非最短 varint；UK 将最短编码作为自身严格约束，不能据此误称 RFC 9000 本身全面禁止其他合法宽度。
- 帧读取使用 256 KiB 分块保留，应用层 payload 有硬上限。F01 说明这些限制没有自动覆盖 QUIC 传输层缓存。
- policy 在规则前拒绝列明的云 metadata 地址，拒绝 Domain 中的 IP literal，对未显式开放 private 的 Allow 拒绝私网/保留地址；相关对抗测试通过。
- 客户端有指数退避和随机 jitter、180 秒 endpoint 降级排序缓存；不是固定 250 ms 无限重连。
- 服务端/客户端常规热重载、TLS/QUIC 证书轮换和常规 drain 测试通过，但未覆盖 F02、F06 的边界路径。
- metrics 格式测试通过；手写 Kubernetes 清单和 Helm 的公开代理 Service 没有包含 9090，Helm metrics Service 为 ClusterIP。

需要后续验证但**未列入已确认远程漏洞**的事项：

| 项目 | 已有证据与局限 | 后续动作 |
| --- | --- | --- |
| 已 abort 的旧 flow 仍可能发送排队 DATA | 真实 reader 等待 carrier 锁后，在 abort 后仍发出旧帧；只有组件复现。复用 ID 下的误投递没有端到端证明，内置客户端通常递增 ID | 核对协议 ID 生命周期，在获取 writer 锁后检查 token/取消状态；补 ID 复用交错验证 |
| SETTINGS 写入缺少专用超时/取消 | 用永不 ready 的 AsyncWrite 证明可持有 session permit 且忽略 shutdown；未验证真实 TCP/QUIC 对端能否稳定触发 | 将 SETTINGS 纳入受限写路径，做实际传输层背压验证 |
| DNS 在拨号 permit 之前 | `lookup_host` 路径使用阻塞解析，取消 future 不等于停止已运行的解析；没有测出 DNS flood/OOM | 在受控慢 DNS 环境验证并发解析上限与取消后的线程/队列回收 |
| AGENTS 文件权限约束未完全落实 | 配置/私钥严格检查；服务器证书读取路径没有同等 0o077 校验，policy 的检查主要限制写权限。这不等于私钥泄露 | 统一文档与实际约束；若坚持证书也必须 0600，补对应校验和部署测试 |
| 发布门禁与真实部署演练缺证据 | release tag 工作流本身不依赖 test/security job；未查远端保护规则、真实发布签名或生产告警交付 | 对 release commit 加硬门禁，记录镜像验证、告警投递、回滚与容量演练 |
| Kubernetes 停机时间预算 | 模板未显式设置 terminationGracePeriodSeconds，而应用默认 drain 也是 30 秒 | 按应用 drain 加余量设 Pod 终止期限，实测滚动更新；Kubernetes 默认 30 秒见[官方说明](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/) |

## 5. 证据强度与边界

所有网络复现仅在本机/隔离副本执行，没有向第三方发送测试流量。合成 CA fixture 来自项目原有测试证书，归档中没有生产密钥。

本次不是形式化验证，也没有完成 24–72 小时耐久、Linux 容器启动、真实 Kubernetes/负载均衡部署、WAN 丢包/抖动、真实多租户负载、完整模糊测试或生产告警链路验证。60 秒 soak 不能替代这些工作，且当前测试规模没有给出可用于生产容量规划的 RSS/FD/线程上限。

QUIC 主动复现因自动安全审查未完成；F01 明确保留为源码证据。其它复现的网络、mock 和调度范围已逐项说明。报告中的风险推断不应改写成未经测量的攻击成功率、吞吐或 OOM 数字。

## 6. 修复顺序与上线验收门槛

1. **先修服务端安全与数据完整性：** F01、F02；审查 SETTINGS 边界；在两种 carrier 上验证拒绝未授权传输资源和停机期间的数据完整性。
2. **再修部署：** F03、F04、F05、F10、F11；同时修完整策略字段序列化。用生产同款非 root 镜像执行 config-check，真实启动 Helm 与手写清单；非授权网络应无法访问 SOCKS 与 metrics。
3. **补生命周期一致性：** F06、F07、F08、F09。把归档复现改成正式回归测试；修复后所有正确性断言通过，异常周转后 flow、permit、定时器、buffer、FD 回归基线。
4. **恢复可信验证链：** 修 F12 和格式问题，原有测试、定向回归、Clippy、MSRV、release build、audit/deny 全绿；发布工作流对最终 release commit 执行或确认这些门禁。
5. **完成生产演练：** 在实际 Linux/Kubernetes 拓扑，以计划峰值和故障条件运行至少一轮长时间负载验证；记录 RSS、FD、线程/任务数、握手与开流成功率、延迟、超时回收。预先定义可接受阈值，验证 SIGHUP、SIGTERM、滚动升级、凭据撤销、告警实际投递与回滚。

只有满足前述门槛并留下可追溯证据后，才能把结论从“暂不建议生产”升级为“适合指定规模和指定部署方式的生产灰度”。当前没有足够依据给出无条件生产可用结论。
