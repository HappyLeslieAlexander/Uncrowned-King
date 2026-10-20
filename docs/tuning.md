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
```

```toml
# client.toml（客户端中均为顶层配置项）
# 提高客户端单会话与单流缓冲队列上限（硬上限 16MB）
max_buffered_bytes_per_session = 16777216 # 16MB
max_buffered_bytes_per_flow = 8388608      # 8MB
```

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
- **UDP 流量优化**：利用 QUIC 原生 `DATAGRAM` 扩展转发 UDP，不引入流控与重传开销。

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
