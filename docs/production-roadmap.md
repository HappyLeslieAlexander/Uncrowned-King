# Uncrowned King 生产化路线图

从当前状态到生产环境的执行计划。范围锁定为**完整 v1**:QUIC DATAGRAM 原生 UDP
为硬性交付项;发布产物同时覆盖**容器镜像**与**裸机/VM + systemd**。

> 状态:计划稿(待审阅)。当前分支 `main` 已合并 QUIC 载体与 rustls-pemfile 迁移,
> 644 测试通过、clippy/fmt 干净、CI 与 RustSec 审计均绿。

---

## 现状基线(已达生产级)

| 领域 | 已具备 |
|---|---|
| 协议正确性 | 严格解析、550+ 单测、5 个 fuzz 目标、TLS/TCP + QUIC 双载体 + 回退 |
| 安全基础 | HMAC + replay cache + TLS/QUIC exporter 绑定 + 常量时间比较;deny-all 策略 + 云元数据 IP 硬拒;密钥 zeroize;文件权限校验;禁 0-RTT |
| 韧性 | 优雅关闭、SIGHUP 热重载、TLS 身份轮换、载体断连 UDP 恢复、全面限流 |
| 可观测 | health/ready/metrics + 18 项 Prometheus 指标 + 结构化 JSON 日志 |
| CI/供应链 | 多工具链 fmt/clippy(-D warnings)/test/release 构建 + RustSec 每日审计 |

**结论**:协议核心接近生产级,差距集中在功能收尾、安全审计、性能验证、发布与运维工程化。

---

## Phase 1 — 协议功能收尾(P0,~1 周)

**目标**:补齐 §19 MVP 剩余项,达成完整 v1 功能面。

- [x] **QUIC DATAGRAM 原生 UDP(§19.6)** — 已完成
  - [x] 将 `quinn::Connection` 经 `DatagramChannel` 抽象穿透到 UDP relay 路径
  - [x] 定义 flow-id 前缀的数据报封装(`uk-proto::datagram`)
  - [x] SETTINGS 协商:QUIC 会话 advertise `supports_udp_datagram = 1`,客户端按协商结果选路
  - [x] 超过 QUIC datagram 大小的载荷回退 `UDP_DATA` 帧路径
  - [x] 单测 + e2e:SOCKS UDP over QUIC 往返 + 超限回退
- [x] **QUIC 证书 SIGHUP 热轮换** — 已完成
  - [x] `endpoint.set_server_config()` 接入安全 reload 流程(先构建两碳载体 crypto 再原子替换)
  - [x] e2e:轮换后新连接用新证书(旧 CA 拒绝/新 CA 成功),存量 QUIC 连接不中断
- [ ] **客户端连接池(§13)**
  - 维护 1 条暖控制连接 + 至多 N 条活跃载体
  - 延迟敏感与批量流量分载体(避免同一 TLS/TCP 载体上混跑)
  - 复用/回收测试

**验收**:§19 MVP 12 项全绿;新增 e2e 覆盖 DATAGRAM;全量测试 + clippy + fmt 绿。

---

## Phase 2 — 安全加固与审计(P0,~1 周)

**目标**:达到可对外承压的安全门禁与文档。

- [x] **威胁模型文档** `docs/threat-model.md`(信任边界、资产、对手、缓解、安全不变量、残余风险)
- [x] **结构化安全自审**(威胁模型逐条映射 §16 控制到实现)
- [x] **`cargo-deny` 接入 CI**:许可证白名单 + 来源 + wildcard/重复依赖门禁(`deny.toml`,本地 `cargo deny check` 全绿)
- [x] **CI fuzz 冒烟**:`fuzz.yml` 跑 5 个 target(本地 nightly+cargo-fuzz 验证:各 20 万次运行无崩溃)
- [x] **密钥/证书管理规范** `docs/key-management.md`(生成、分发、权限、轮换、吊销 SOP)
- [x] `SECURITY.md`(漏洞披露流程、范围、SLA)

**验收**:安全自审清单全过;`cargo-deny` 与 fuzz 冒烟纳入 CI 且绿。 — **已达成**

---

## Phase 3 — 性能与稳定性验证(P1,~1 周)

**目标**:用数据证明满足 §13 性能要求,并验证长时稳定性。

- [x] **codec 微基准**(criterion):varint/frame/target/datagram/settings 编解码 — 每包 <100 ns,证明 codec 非瓶颈
- [x] **§13 对照**:分方向计数器、DATAGRAM、自适应回退已具备(见 `docs/performance.md` 对照表);`RELAY_BUFFER_SIZE` 16→32 KiB 暂缓——首次尝试触发 Linux-only 大载荷/即时关闭 e2e "early eof",改到 e2e 吞吐 harness(可在 Linux 复现)下落地+验证
- [ ] **端到端吞吐/延迟**(真实 socket,client→server→target):TCP/UDP × QUIC/TLS,P50/P99 + 持续吞吐
- [ ] **长时 soak(≥24h)+ chaos**:反复断载体、限流边界、句柄/内存监控
- [ ] **真实互操作**:curl / 浏览器经 SOCKS5 走通 TCP + UDP(DNS),QUIC 与 TLS 各一遍
- [x] 记录性能基线到 `docs/performance.md`(codec 基线 + §13 对照 + 待办)

**验收**:达成 §13 目标且有数据;soak 无内存泄漏、无句柄增长、无错误累积。

---

## Phase 4 — 发布工程(P1,~4-6 天)

**目标**:一键产出可分发、可验证的发布产物(容器 + 二进制双轨)。

- [ ] 语义化版本 + `CHANGELOG.md` + 打 `v0.1.0` tag
- [ ] **跨平台 release 工作流**:linux/macos × x86_64/arm64 静态二进制
- [ ] **容器镜像**:distroless / 非 root,多架构(amd64/arm64)
- [ ] **SBOM**(cargo-cyclonedx)+ 产物 SHA256 校验和 + 签名(cosign/minisign)
- [ ] 发布产物冒烟:容器与二进制各起一次 `config-check` + 端到端连通

**验收**:tag 触发 release,自动产出并发布镜像 + 二进制 + SBOM + 校验和。

---

## Phase 5 — 运维就绪(P1,~4-6 天)

**目标**:他人可按文档独立部署上线并监控。

- [ ] **systemd unit**(非 root、能力最小化、`ProtectSystem`、资源限制)+ 裸机部署文档
- [ ] **K8s 产物**:Deployment/Service manifest 或 Helm chart,liveness/readiness 接 `/healthz` `/readyz`
- [ ] **Grafana dashboard + Prometheus 告警规则**示例(握手失败率、拒绝率、活跃会话、relay 字节、reload 失败)
- [ ] **运维手册** `docs/operations.md`:容量规划、参数调优、故障排查、密钥轮换、升级/回滚

**验收**:按文档在容器与裸机两种形态各完成一次干净部署 + 监控告警触达验证。

---

## Phase 6 — 上线 Gate(~2-3 天)

- [ ] 金丝雀/灰度方案(小流量 → 观察指标 → 放量)
- [ ] 回滚预案(镜像/二进制回退 + 配置回退)
- [ ] 监控告警接入生产 Prometheus/Alertmanager 并验证触达
- [ ] 上线检查清单签核

---

## 关键路径与依赖

```
Phase 1 (功能) ─┬─> Phase 3 (性能, 依赖功能定型)
                └─> Phase 4 (发布, 依赖功能定型)
Phase 2 (安全) ──> 可与 Phase 1 并行,是上线 Gate 的前置
Phase 4 (发布) ──> Phase 5 (运维, 依赖产物)  ──> Phase 6 (Gate)
```

- **P0(阻断上线)**:Phase 1、Phase 2
- **P1(上线必备)**:Phase 3、Phase 4、Phase 5
- **总工期估算**:约 **4-5 周**(单人;Phase 1/2 并行可压到 ~4 周)

## 里程碑

| 里程碑 | 含义 | 覆盖 |
|---|---|---|
| M1 功能冻结 | §19 MVP 全绿,含 DATAGRAM | Phase 1 |
| M2 安全签核 | 威胁模型 + 门禁齐备 | Phase 2 |
| M3 性能达标 | §13 数据达标 + soak 通过 | Phase 3 |
| M4 可发布 | 产物 + 签名 + SBOM | Phase 4 |
| M5 可运维 | 双形态部署 + 监控告警 | Phase 5 |
| GA 上线 | 灰度 + 回滚就绪 | Phase 6 |

## 未纳入 v1(记录在案)

- HTTP/2 与 WebSocket 载体(§3.1,白皮书列为原生载体之后)
- 多密钥/密钥分组的动态后端(当前静态凭证 + policy_group 已够用)
