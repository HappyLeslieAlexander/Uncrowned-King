# Uncrowned King 生产环境性能调优指南

本文档提供在不同部署环境（局域网低延迟、广域网跨地域高丢包、高并发网关）下的系统参数调优与推荐配置。

---

## 1. 核心配置参数推荐

### 1.1 高吞吐场景（大文件传输 / 视频流 / 备份同步）
适用于带宽充裕（> 100Mbps）且并发连接数适中的环境：

```toml
# server.toml
[limits]
# 增加帧大小上限（默认 64KB，硬上限 16MB）
max_frame_size = 65536

# 增加中继数据块大小（支持 1KB ~ 1MB，推荐 64KB ~ 128KB）
relay_buffer_size = 65536

# 提高单会话和单流允许的缓冲队列上限，防止大吞吐时频繁触发背压暂停（硬上限 16MB）
max_buffered_bytes_per_session = 16777216 # 16MB
max_buffered_bytes_per_flow = 8388608      # 8MB

# 调整 QUIC 单流与连接级流控接收窗口（默认 1MB，支持 64KB ~ 16MB）
# 连接窗口必须大于等于单流窗口。跨国高带宽大延迟（高 BDP）链路建议调高
quic_stream_receive_window = 4194304      # 4MB
quic_connection_receive_window = 8388608  # 8MB
```

```toml
# client.toml（客户端中均为顶层配置项）
# 提高客户端单会话与单流缓冲队列上限（硬上限 16MB）
max_buffered_bytes_per_session = 16777216 # 16MB
max_buffered_bytes_per_flow = 8388608      # 8MB
```

### 1.1.1 UDP 报文尺寸（默认 16 KiB）

UDP 数据报的有效载荷上限是 `data_frame_size = min(max_frame_size, relay_buffer_size)`，
默认 `relay_buffer_size = 16384`（16 KiB）：超过该尺寸的 UDP 数据报会被**丢弃并记录
`client.udp.datagram.too_large`**（计数的还有
`uncrowned_king_client_udp_association_queue_full_total`，即目标队列溢出丢包），不会静默截断。
DNS 等典型小报文不受影响；需要承载大 UDP 载荷（如 WireGuard/QUIC 隧道内再封装）的部署需
在**服务端与客户端同时**调大 `relay_buffer_size`（两端 `data_frame_size` 取小者生效），并
相应调高 `max_buffered_bytes_per_flow` / `max_buffered_bytes_per_session`，因为每个在途
报文都会占用流/会话缓冲预算。`max_frame_size` 只放宽帧的上限，不足以单独提升 UDP 尺寸。

### 1.2 高并发网关场景（微服务集群 / 爬虫 / IoT 设备接入）
适用于海量并发短连接、活跃流数量极多的场景：

```toml
# server.toml
[limits]
# 提高最大支持的并发客户端会话数与握手并发量
max_sessions = 50000
max_handshakes = 2000

# 提高单个载体上允许的最大并发流数
max_streams = 4096
max_udp_flows = 2048

# 减小单流缓冲，保证海量流不会耗尽服务端内存
relay_buffer_size = 16384                  # 16KB
max_buffered_bytes_per_flow = 1048576      # 1MB
max_buffered_bytes_per_session = 16777216  # 16MB（硬上限 16MB）

# 缩短空闲流清理超时，加速释放非活跃资源
idle_timeout_seconds = 60
udp_flow_idle_timeout_seconds = 30
```

### 1.3 弱网 / 跨国跨境链路场景
- **传输载体建议**：优先选用 **QUIC 载体**。QUIC 基于 UDP，具备抗丢包能力、多路复用无队头阻塞（HOL Blocking）以及 0-RTT/1-RTT 极速连接特性。
- **QUIC 接收窗口调优**：对于高丢包但有较大带宽延时积（BDP）的跨国链路，建议将 `limits.quic_stream_receive_window` 调至 `4194304` (4MB)，并将 `limits.quic_connection_receive_window` 调至 `8388608` (8MB)，避免传输层过早触发 QUIC 流控窗口等待。
- **UDP 流量优化**：利用 QUIC 原生 `DATAGRAM` 扩展转发 UDP，不引入流控与重传开销。
- **已知限制：半开 TLS/TCP 载体上的 UDP 丢包窗口**：客户端只复用未被标记关闭的会话；一个"半开"载体（对端已不可达但尚未收到 RST/FIN，`is_closed()` 仍为 false）在检测落地前会把 UDP 报文写入已死的内核缓冲区并静默丢失。检测延迟有上界：QUIC 载体为 keep-alive 15s + idle timeout 60s；TLS/TCP 载体为 `idle_timeout_seconds / 2` 的 keepalive PING（服务端默认 300s 时最长约 150s）。对 UDP 可用性敏感的部署，优先使用 QUIC 载体，或调低服务端 `idle_timeout_seconds` 以缩短半开窗口。

---

## 2. 操作系统内核网络参数优化 (Linux sysctl)

在高并发生产宿主机上，建议调整以下 Linux 内核参数：

```ini
# /etc/sysctl.d/99-uncrowned-king.conf

# 增加系统最大打开文件句柄数 (FD)
fs.file-max = 2097152

# TCP 读写缓冲区最大值与默认值 (适用于 BDP 较大的长肥网络)
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# UDP 缓冲区大小 (针对 QUIC 高速传输)
net.core.optmem_max = 2048576

# 开启 TCP BBR 拥塞控制算法
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 连接队列深度与 TIME_WAIT 快速回收
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
```

执行生效命令：
```bash
sudo sysctl --system
```

---

## 3. 基准测试执行

执行内置吞吐与并发基准测试：

```bash
# 1. 运行所有 benchmark
cargo bench

# 2. 运行 E2E 吞吐与隔离测试（包含 --ignored 基准测试）
cargo test -p uk-client --test tcp_relay_e2e -- --ignored --nocapture
```

## 5. Transport masking interactions

- **QUIC MTU**: with `masking.quic` enabled, MTU discovery's upper bound is
  capped at 1440 (unmasked default 1452 minus the 12-byte per-segment nonce),
  so masked datagrams never exceed the plain carrier's path-MTU budget. QUIC's
  clamped initial/min MTU (1200) is unaffected; `1200 + 12` stays below every
  realistic path MTU.
- **Handshake budgets**: the masking prelude is read under
  `handshake_timeout_seconds`; rejected connections are drained until the same
  deadline, so raising it also lengthens the silent-drain window (bounded by
  the 4 KiB / 64-read budget).
- **Credential count**: see `docs/operations.md` — prelude verification is
  linear in the credential count with no early exit.
