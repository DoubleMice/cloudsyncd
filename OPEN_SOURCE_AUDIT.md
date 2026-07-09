# cloudsyncd 安全与发布检查

审计日期：2026-06-24
仓库状态：私人部署仓库，准备推送到私有 GitHub 仓库

## 结论摘要

当前代码已经完成了基础加固，可以作为私人部署仓库保存和同步，但仍不应把 Node 服务端口直接暴露到公网。推荐入口是 Cloudflare Tunnel 或 SSH 端口转发，并在需要时叠加 Cloudflare Access。

当前树相对早期版本的重要变化：

1. Python 自动下载客户端已从仓库移除，`shared/` 现在只作为运行态共享目录使用。
2. 保护接口已加入逐请求 HMAC、时间窗和 nonce 重放防护。
3. 已加入设备撤销、全部撤销、主密钥轮换、可选管理 Token 轮换和本地共享文件管理。
4. 管理端拆到独立本地端口，默认只绑定 `127.0.0.1`。
5. `LICENSE` 已存在，`tar` 依赖已升级到当前安全版本。

## Git 与敏感文件

必须保持忽略：

- `data/state.json`: 主密钥、已配对设备清单、可选管理 Token
- `data/.admin-token`: 可选管理 Token 副本
- `shared/`: 运行态共享载荷
- `.env*`: 本地环境变量
- `.cloudflared/`、`*.pem`、`*.key`、Cloudflare 凭证和日志
- `.syncd_key`、`.syncd_state.json`: 旧客户端或下载目录中可能出现的本地状态

检查命令：

```bash
git status --short
git ls-files
```

如果未来要公开仓库，先检查 Git 历史中是否出现过真实域名、邮箱、隧道 UUID、绝对凭证路径或运行态样本。

## 当前鉴权模型

客户端配对分两步：

1. 使用 6 位 PIN + ECDH / HKDF 协商主密钥。
2. 后续受保护请求携带 `X-Device-Id`、`X-Auth-Timestamp`、`X-Auth-Nonce`、`X-Auth-Signature`。

服务端会校验：

- 设备 ID 是否仍在配对清单中
- 时间戳是否在允许窗口内
- nonce 是否重复使用
- HMAC 是否覆盖请求方法、路径、时间戳、nonce 和请求体 hash

设备撤销会立即让该设备的后续请求失败。主密钥轮换会清空全部设备，并要求所有客户端重新配对。

## 管理面边界

管理端运行在独立 Express app 上，默认：

- 客户端端口：`127.0.0.1:21891`
- 管理端口：`127.0.0.1:21900`

Cloudflare Tunnel 配置只转发客户端端口，不转发管理端。公网域名访问 `/admin`、`/admin.js`、`/api/local/*` 不会命中管理服务。远程管理应通过 SSH 端口转发访问 `127.0.0.1:21900`。默认本地回环管理端不要求 Token；设置 `ADMIN_AUTH=1` 或把 `ADMIN_HOST` 暴露到非回环地址时才要求管理 Token。

不要在没有额外网络控制的情况下把 `ADMIN_HOST` 改成 `0.0.0.0`。

## 仍需接受的风险

- 主密钥和可选管理 Token 明文保存在本机 `data/state.json`，依赖主机文件权限和 `.gitignore` 隔离。
- 浏览器客户端会把主密钥保存在 IndexedDB；大文件后台下载会把本次下载所需密钥短暂交给同源 Service Worker，浏览器账户或终端被入侵时可能泄露。
- 所有设备共享同一个主密钥，没有每设备独立内容密钥或单设备 ACL。
- `shared/` 下所有非隐藏文件都会对已配对设备可见；本地管理端可以搜索、上传、单个删除、多选删除或清空这些共享文件。
- 文本消息只保存在服务进程内存中，重启后丢失。
- Cloudflare Tunnel 只做入口转发；如需用户身份控制，应另配 Cloudflare Access。
- 浏览器客户端和管理端会加载 Google Fonts；如果需要完全自托管前端，应改为系统字体或本地字体文件。

## Cloudflare 部署说明

仓库只应保留 `cloudflared-config.example.yml` 模板。真实的 `cloudflared-config.yml` 属于本地部署配置，包含：

- 隧道 UUID 或名称
- 本机 `~/.cloudflared/...json` 凭证路径
- 入口域名

这些值不等同于凭证本体，但属于部署信息，当前应保持 `.gitignore` 忽略。若这些值曾经被推送到远端，普通提交只能清理当前树，不能清理 Git 历史；公开发布前应考虑重写历史或重新创建 / 轮换 Cloudflare Tunnel。

## 发布建议

私有仓库推送前：

1. 确认 `data/` 和 `shared/` 未被跟踪。
2. 确认没有 `.env`、Cloudflare 凭证、日志、下载缓存。
3. 运行 `npm audit --omit=dev`。
4. 运行 `node --check` 检查入口脚本语法。

公开仓库发布前还应额外完成：

1. 模板化 Cloudflare 域名、隧道 UUID 和绝对路径。
2. 检查历史提交中的个人邮箱和部署信息。
3. 明确说明该项目不提供公网直连安全保证。
4. 如保留 Cloudflare 部署章节，改成通用示例而不是个人配置。
