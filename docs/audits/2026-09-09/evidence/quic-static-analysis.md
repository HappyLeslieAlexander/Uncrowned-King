# QUIC 认证前资源预算：静态证据

项目位置：`crates/uk-server/src/quic.rs:69–76` 创建默认 QuinnServerConfig；第 136–141 行仅打开服务端发起的控制流。当前代码未设置 max_concurrent_bidi_streams、max_concurrent_uni_streams、stream_receive_window 或 receive_window。

检查的是 Cargo.lock 锁定的 `quinn-proto 0.11.16`，本地依赖源码 `src/config/transport.rs`：

| 默认字段 | 实际值 | 源码位置 |
| --- | --- | --- |
| max_concurrent_bidi_streams | 100 | 362 |
| max_concurrent_uni_streams | 100 | 363 |
| stream_receive_window | 1,250,000 bytes | 354–366，带宽 12,500,000 bytes/s × RTT 0.1s |
| receive_window | VarInt::MAX | 367 |

该类型注释指出，不允许对端发起流的应用协议应把两个 max_concurrent 字段设为零；其字段文档指出最坏内存量级与流数乘每流接收窗口相关，并受连接总窗口约束。

因此项目的额外远端流许可对应 200 × 1,250,000 = 250,000,000 bytes（约 238.4 MiB）传输数据窗口。这不是启动时立即分配量，不是实测 RSS，也不是完整进程内存上界；真实内存还受包开销、网络速率、连接持续时间与其他缓冲影响。

`max_pre_auth_bytes=4096` 检查的是 UK 控制帧，不能作用于未交给 UK parser 的额外 QUIC 流。TLS 握手本身不要求客户端证书；UK HMAC 是其后的应用层认证。认证超时不能替代接收窗口预算。

主动本地复现尝试被工具自动安全审查拦截，没有可归档的成功网络复现。报告只依据上述源码证据提出 F01，不宣称已测得 OOM 或实际成功写入任何指定数量的数据。

建议的安全修复方向：禁用不使用的远端流；对协议必需控制流、整个 connection 和 DATAGRAM 接收缓冲制定明确内存预算，并验证这些预算与 max_handshakes/max_sessions 的乘积适配部署内存。无需发送高流量即可先测试实际公布的 transport parameters 是否符合协议。
