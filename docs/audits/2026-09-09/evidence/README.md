# 审查证据索引

对应报告：[2026-09-09 生产审查报告](../PRODUCTION_AUDIT_2026-09-09.md)。

本目录仅包含报告附件、合成测试证书、未应用到项目的复现补丁和实际日志。所有复现必须在隔离副本执行；测试断言表达修复后的正确行为，因此在审查版本上失败属于预期证据。

## 检查日志

- `checks/workspace-tests.log`：当前工作区全部常规测试，850 通过、3 忽略。
- `checks/clippy.log`、`msrv.log`、`release.log`、`doc.log`：实际检查结果。
- `checks/fmt.log`：已有未提交测试文件的格式检查失败。
- `checks/cargo-audit.json`：RustSec 数据库时间、提交与零已知漏洞结果。
- `checks/deny.log`：依赖策略审查通过，包含 windows-sys 重复版本警告。
- `checks/interop.log`：官方 curl 互通脚本实际失败。
- `checks/soak-summary.log`：60 秒 release soak 结果；已省略大量预期 policy.denied 日志，保留命令和最终统计。
- `reviewed-files-sha256.json`：审查工作区已跟踪文件的 SHA-256，包括用户原有未提交修改；不是对远程 release 的校验。

## 缺陷复现

- `client/README.md`、`client/audit-tests.patch`、`client/reproduction.log`：F06、F07、F08。两个 PEM 文件为项目原有合成 CA 测试 fixture，没有私钥。
- `server/README.md`、`server/server-review-tests.patch`、`server/server-review-tests.log`：F02、F09 与两个待验证风险。包含完整 relay_session 上传截断测试。
- `server/reproduce.sh`：复制源文件到临时目录后应用 server 测试补丁；不修改生产源码。
- `deployment/helm.yaml`、`deployment/helm-both.yaml`：实际 Helm 渲染；仅使用合成 existingSecret 名称，未访问集群。
- `deployment/config-check.log`：F03 的三个阶段性校验失败。
- `deployment/reproduce.py`：在临时目录创建合成证书/凭据，重现渲染 TOML 的三个错误；不部署任何资源。
- `quic-static-analysis.md`：F01 的锁定依赖默认值与静态推断边界；无主动流量复现。

报告和证据的主路径使用审查时的本机绝对路径。移到其它机器后，可按目录中的文件名定位；复现时使用本机项目路径。
