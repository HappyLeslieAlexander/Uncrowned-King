# 贡献指南 (Contributing Guide)

感谢您对 **Uncrowned King** 项目的关注与贡献！为了保证代码质量、安全性与长期可维护性，请在提交代码前遵循以下开发流程与规范。

---

## 1. 开发环境要求

- **Rust Toolchain**：Rust 1.85.0+ (MSRV)
- **Cargo 扩展工具**：`rustfmt`, `clippy`
- **可选工具**：`cargo-deny`, `cargo-fuzz`, `helm`, `docker`

---

## 2. 本地开发与验证流程

每次提交 PR 前，请确保以下所有检查命令本地 100% 通过：

```bash
# 1. 格式化检查
cargo fmt --all --check

# 2. 严格 Clippy 静态代码分析 (不允许任何 warning)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# 3. 运行全工作区单元测试与集成测试
cargo test --workspace

# 4. 文档构建与链接有效性检查
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# 5. 依赖许可证与漏洞审计 (若已安装 cargo-deny)
cargo deny check
```

---

## 3. 代码与架构规范

1. **分层原则**：
   - 基础类型与编解码协议放在 `uk-proto`，避免引入不必要的重量级运行时依赖。
   - 鉴权与密码学操作放在 `uk-auth`，所有私钥与 Secret 必须实现 `Zeroize` 并提供防时序攻击比较。
   - 路由与访问控制放在 `uk-policy`。
   - 服务端与客户端逻辑分别隔离在 `uk-server` 和 `uk-client` 中。
2. **错误处理**：
   - 库内部使用专有强类型 Error 枚举（如 `ProtocolError`, `AuthError`, `PolicyError`）。
   - 顶层边界函数使用标准 `std::error::Error`。
3. **日志与可观测性**：
   - 使用 `tracing` 进行结构化日志记录，严禁将未脱敏的凭证或敏感数据写入日志。
   - 关键路径更新 Prometheus 指标。

---

## 4. 提交规范 (Git Commit Convention)

请遵循 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

- `feat(scope): ...`：新功能
- `fix(scope): ...`：漏洞或 Bug 修复
- `perf(scope): ...`：性能优化
- `refactor(scope): ...`：重构（无功能变更）
- `docs(scope): ...`：文档补充或更新
- `test(scope): ...`：测试新增或补充
- `ci(scope): ...`：CI/CD 运维配置变更
