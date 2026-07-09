# cloudsyncd

原始仓库: https://github.com/toads/cloudsysncd

轻量的 Node.js 文件 / 文本同步服务。分享端通过一次性 PIN 配对接收端；配对后请求使用 `deviceId + timestamp + nonce + HMAC` 鉴权，文件和文本在传输时加密。

默认只监听本机回环地址，适合配合 Cloudflare Tunnel 或 SSH 端口转发使用，不建议直接暴露 Node 服务端口。

![cloudsyncd client web interface](./docs/client_web.png)

## 快速开始

```bash
npm install
npm link                 # 可选：安装 cloudsyncd 命令
```

终端 1：

```bash
cloudsyncd server start
```

终端 2：

```bash
cloudsyncd server share add ./file.pdf
cloudsyncd server pin
```

默认端口：

- 接收端页面: `http://127.0.0.1:21891`
- 本地管理端: `http://127.0.0.1:21900/admin`（本机直接打开，无需登录）

本地管理端可生成 PIN、撤销设备、轮换主密钥，并搜索、上传、单个删除、多选删除或清空 `shared/` 共享文件。

第一次接收时会触发配对：

```bash
cloudsyncd client list https://your-sync-host.example
cloudsyncd client get https://your-sync-host.example "dir/file.pdf"
```

浏览器接收端支持大文件分块解密和认证完成校验；支持 Service Worker 时，大文件由浏览器下载管理器接管，离开页面后仍可继续下载。不可用时回退到 File System Access 流式写入。CLI 的 `cloudsyncd client get` 也使用分块流式解密，适合大文件和自动化下载。

没有全局安装时也可以直接运行：

```bash
node bin/cloudsyncd.js --help
npm exec -- cloudsyncd --help
```

卸载全局命令：

```bash
npm unlink -g cloudsyncd
npm uninstall -g cloudsyncd   # 如果曾用 npm install -g . 安装
```

## 常用命令

分享端：

```bash
cloudsyncd server start
cloudsyncd server start --tunnel
cloudsyncd server status

cloudsyncd share ./file.pdf
cloudsyncd share --copy ./file.pdf
cloudsyncd share list
cloudsyncd share clear

cloudsyncd server pin
cloudsyncd server devices
cloudsyncd server revoke <device-id>
cloudsyncd server revoke-all
cloudsyncd server rotate-key
cloudsyncd server rotate-token  # 仅在启用 ADMIN_AUTH=1 或暴露 ADMIN_HOST 时需要
```

接收端：

```bash
cloudsyncd client list <share-url>
cloudsyncd client get <share-url> <remote-path> [-o <path>] [--force]
cloudsyncd client batch <share-url> [-o <file.tar.gz>] [--since <ISO>]
cloudsyncd client logout <share-url>
```

`client get` 会流式分块解密并原子替换输出文件；目标文件已存在时需加 `--force`。

完整菜单以 CLI 为准：

```bash
cloudsyncd --help
```

## Cloudflare Tunnel

固定域名使用 named tunnel：

```bash
cloudflared tunnel login
cloudflared tunnel create sync
cp cloudflared-config.example.yml cloudflared-config.yml
cloudsyncd server tunnel setup
cloudsyncd server start --tunnel
```

`cloudflared-config.yml` 是本地私有配置，包含 tunnel ID、hostname 和 credentials 路径，已被 `.gitignore` 忽略。

Tunnel 生命周期：

```bash
cloudsyncd server tunnel validate
cloudsyncd server tunnel route-dns sync.example.com
cloudsyncd server tunnel start
cloudsyncd server tunnel stop
```

公网 502 通常表示 Cloudflare 到了，但本机 origin 没响应。按这个顺序查：

```bash
curl -i http://127.0.0.1:21891/api/status
lsof -nP -iTCP:21891 -sTCP:LISTEN
tail -n 80 /tmp/cloudflared-sync.log
curl -i https://your-sync-host.example/api/status
```

## Client 侧网络错误

如果 `cloudsyncd client list <share-url>` 报网络错误，先从接收端检查：

```bash
curl -i https://your-sync-host.example/api/status
```

判断：

- `curl` 失败：URL、DNS、TLS、代理、防火墙或 Tunnel 不通。
- 返回 `502`：分享端 origin 没响应，检查 `cloudsyncd server start --tunnel` 和 `127.0.0.1:21891`。
- 返回 `200`：网络通，检查 PIN 或旧 profile。需要时执行 `cloudsyncd client logout <share-url>` 后重新配对。

新版 CLI 会把旧的 `Error: fetch failed` 展开成失败 URL、底层错误码和排障提示。

## 架构

![cloudsyncd runtime topology](./docs/diagrams/runtime-topology.png)

更多图和协议说明见 [docs/architecture.md](./docs/architecture.md)。

## 目录

- `bin/`: CLI 入口
- `lib/`: CLI、接收端 profile 和协议 helper
- `server.js`: 分享端服务
- `public/`: 浏览器接收端
- `admin/`: 本地管理面板
- `docs/`: 架构说明、截图和图表
- `cloudflared-config.example.yml`: Tunnel 配置模板

运行态目录默认忽略，不应提交：

- `data/`: 主密钥、设备列表、可选管理 Token
- `shared/`: 分享载荷
- `downloads/`: 接收端下载
- `cloudflared-config.yml`、`.cloudflared/`: 本地 Tunnel 配置和凭证
- `node_modules/`: 本地依赖

npm 包由 `package.json` 的 `files` 白名单控制，不包含 `test/`、`data/`、`shared/`、日志、下载缓存或本地 Cloudflare credentials。

## 安全边界

- `data/state.json` 含主密钥、设备列表和可选管理 Token，必须保持忽略；服务端启动时会把 `data/` 收紧到 `0700`，把密钥文件收紧到 `0600`。
- `shared/` 中的文件会对已配对设备可见。
- 浏览器接收端会把主密钥保存在 IndexedDB；大文件后台下载时会把本次下载所需密钥短暂交给同源 Service Worker，仅保存在内存中。
- 所有已配对设备共享同一个主密钥；轮换主密钥后全部设备需要重新配对。
- Cloudflare Tunnel 只提供入口转发，不替代应用层鉴权；需要额外门禁时配置 Cloudflare Zero Trust Access。
- 本地管理端默认只绑定 `127.0.0.1:21900`，本机打开不需要认证；设置 `ADMIN_AUTH=1` 或将 `ADMIN_HOST` 暴露到非回环地址时会启用 Token 认证。

发布前检查项见 [OPEN_SOURCE_AUDIT.md](./OPEN_SOURCE_AUDIT.md)。
