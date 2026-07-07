# cloudsyncd

原始仓库: https://github.com/toads/cloudsysncd

一个轻量的 Node.js 文件 / 文本同步服务。服务端生成一次性 PIN，浏览器客户端通过 ECDH + HKDF 协商主密钥；配对后的受保护请求使用 `deviceId + timestamp + nonce + HMAC` 做逐请求鉴权，文件与文本内容在传输时加密。

当前仓库按私人部署维护。默认服务只绑定本机回环地址，适合通过 Cloudflare Tunnel 或 SSH 端口转发访问，不建议把 Node 服务端口直接暴露到公网。

架构图和关键协议流程见 [docs/architecture.md](./docs/architecture.md)。

![cloudsyncd client pairing screen](./docs/client_web.png)

## 架构图

### 运行拓扑

![cloudsyncd runtime topology](./docs/diagrams/runtime-topology.png)

### 配对和下载流程

![cloudsyncd pairing and protected download](./docs/diagrams/pairing-download-sequence.png)

### Tunnel 502 排障

![cloudsyncd Cloudflare Tunnel 502 troubleshooting](./docs/diagrams/tunnel-502-troubleshooting.png)

## 功能

- 浏览器端 PIN 配对
- `shared/` 运行态目录文件共享、单文件下载和批量下载
- 文本共享接口
- 配对设备列表、单设备撤销、全部撤销
- 主密钥轮换和管理 Token 轮换
- 本地管理面板（Admin UI）
- 可选 Cloudflare Tunnel 部署

## 目录说明

- `server.js`: Express 服务端，同时启动客户端端口和本地管理端口
- `public/`: 浏览器客户端页面
- `admin/`: 本地管理面板
- `docs/architecture.md`: 运行拓扑和配对 / 下载流程图
- `pin.js`: 通过本地管理端口生成新 PIN
- `devices.js`: 设备列表、撤销、主密钥轮换、管理 Token 轮换
- `share.js`: 把文件或目录加入 `shared/`，默认使用硬链接，失败时回退复制
- `cloudflared-config.example.yml`: Cloudflare Tunnel 配置模板
- `cloudflared-config.yml`: 本地私有 Tunnel 配置，默认忽略，不提交
- `data/`: 运行时状态，保存主密钥、已配对设备和管理 Token，必须保持忽略
- `shared/`: 运行时共享载荷目录，必须保持忽略

## 环境要求

- Node.js 20+
- npm 10+
- `cloudflared`（仅在使用 Cloudflare Tunnel 时需要）

## 快速开始

```bash
npm install
node bin/cloudsyncd.js server start
```

默认启动两个本地监听端口：

- 客户端：`http://127.0.0.1:21891`
- 管理端：`http://127.0.0.1:21900/admin`

首次启动时，如果没有已配对设备，服务端会在终端打印 6 位 PIN。打开客户端页面输入 PIN 完成配对后即可浏览和下载 `shared/` 中的文件。

## CLI 安装与卸载

不安装全局命令时，可以在仓库目录内临时使用：

```bash
node bin/cloudsyncd.js --help
node bin/cloudsyncd.js client list https://your-sync-host.example
```

也可以通过 npm 解析本地 bin：

```bash
npm exec -- cloudsyncd --help
```

开发或本机长期使用时，推荐链接为全局命令：

```bash
npm install
npm link
```

注意：`npm install` 只安装依赖，不会把当前仓库的 `cloudsyncd` 命令加入 `PATH`。需要执行 `npm link`，或使用上面的 `node bin/cloudsyncd.js` / `npm exec -- cloudsyncd` 临时方式。

验证：

```bash
cloudsyncd --help
cloudsyncd server share list
```

卸载全局命令：

```bash
npm unlink -g cloudsyncd
```

如果是通过 `npm install -g .` 安装的，使用：

```bash
npm uninstall -g cloudsyncd
```

检查命令是否仍在 `PATH` 中：

```bash
command -v cloudsyncd
```

卸载 CLI 不会删除接收端 profile。如需清理本机保存的接收端配对状态：

```bash
rm -rf ~/.config/cloudsyncd
```

## 统一 CLI

CLI 明确区分两个角色：

- `server`: 分享端，在运行服务和管理 `shared/` 的机器上执行
- `client`: 接收端，在下载文件的机器上执行

### 分享端（server）

启动服务：

```bash
cloudsyncd server start
cloudsyncd server start --tunnel     # 同时启动 Cloudflare Tunnel
```

加入共享文件或目录：

```bash
cloudsyncd server share add file1.pdf dir1 another.txt
cloudsyncd server share add --copy file1.pdf      # 强制复制，不使用硬链接
```

快捷写法等价于 `server share add`，相对路径按你执行命令时所在目录解析：

```bash
cloudsyncd share dist/offline/patch.tar.gz
cloudsyncd share --copy ./dist/offline/patch.tar.gz
```

查看或清空共享目录：

```bash
cloudsyncd server share list
cloudsyncd server share clear
cloudsyncd share list
cloudsyncd share clear
```

为新设备生成 PIN：

```bash
cloudsyncd server pin
```

列出 / 撤销已配对设备：

```bash
cloudsyncd server devices
cloudsyncd server revoke <id>
cloudsyncd server revoke-all
cloudsyncd server rotate-key
cloudsyncd server rotate-token
```

撤销会立即把设备从服务端清单中移除，后续请求会被拒绝。撤销单个设备不会轮换主密钥；如果怀疑主密钥泄露，使用 `--rotate-key` 强制所有设备重新配对。

### 接收端（client）

接收端第一次访问分享端时会自动触发配对。先在分享端运行 `cloudsyncd server pin` 生成 PIN，然后在接收端执行：

```bash
cloudsyncd client list https://your-sync-host.example
cloudsyncd client get https://your-sync-host.example "dir/file.pdf"
cloudsyncd client batch https://your-sync-host.example --since 2026-07-01T00:00:00.000Z
```

非交互脚本可以直接传 PIN：

```bash
cloudsyncd client get https://your-sync-host.example "dir/file.pdf" --pin 123456
```

接收端 profile 保存在 `~/.config/cloudsyncd/client-profiles.json`，按分享端 URL 分组。设备被撤销或分享端轮换主密钥后，下一次 `client list/get/batch` 收到 401 会自动提示重新配对并重试一次。

兼容旧脚本仍然可用：`node share.js`、`node pin.js`、`node devices.js`。

## 管理端

管理端是 `devices.js` / `pin.js` 的图形化版本，只绑定本机回环地址。Cloudflare Tunnel 只转发客户端端口 `21891`，所以公网域名不会暴露 `/admin`、`/admin.js` 或 `/api/local/*`。

打开：

```text
http://127.0.0.1:21900/admin
```

远程管理时使用 SSH 端口转发：

```bash
ssh -L 21900:127.0.0.1:21900 user@server
```

管理 Token 在服务器 `data/.admin-token` 文件中，持久化在 `data/state.json`，重启不会变化。可以在管理面板中轮换，也可以运行 `node devices.js --rotate-token`。

## 环境变量

- `PORT`: 客户端监听端口，默认 `21891`
- `HOST`: 客户端绑定地址，默认 `127.0.0.1`
- `ADMIN_PORT`: 管理端监听端口，默认 `21900`
- `ADMIN_HOST`: 管理端绑定地址，默认 `127.0.0.1`
- `WITH_TUNNEL`: 设为 `1` 时，`cloudsyncd server start` 或 `start.sh` 会同时拉起 Cloudflare Tunnel
- `TUNNEL_CONFIG`: Cloudflare Tunnel 配置文件路径，默认 `cloudflared-config.yml`
- `TUNNEL_NAME`: Cloudflare Tunnel 名称，默认 `sync`

只有在清楚网络边界时才把 `HOST` 或 `ADMIN_HOST` 改成 `0.0.0.0`。管理端通常应始终保持本机可达。

## Cloudflare Tunnel

仓库只保留 `cloudflared-config.example.yml` 模板。真实的 `cloudflared-config.yml` 包含 tunnel ID、hostname 和凭证文件路径，默认被 `.gitignore` 忽略，不应提交。

首次使用固定域名的 named tunnel 时，需要先准备 Cloudflare 侧 tunnel 和本地配置文件。`cloudsyncd server tunnel start` 不会自动创建 tunnel，也不会自动生成 `cloudflared-config.yml`。

```bash
cloudflared tunnel login
cloudflared tunnel create sync
cp cloudflared-config.example.yml cloudflared-config.yml
```

然后编辑 `cloudflared-config.yml`，填入：

- `tunnel`: 你的 tunnel ID 或名称
- `credentials-file`: `cloudflared tunnel create` 生成的 credentials JSON 路径
- `ingress[0].hostname`: 要绑定的公网域名

目标拓扑是将你的公网 hostname 转发到本机 `127.0.0.1:21891`。

配置文件填好后，可以一键完成本地 ingress 校验和 DNS hostname 绑定：

```bash
cloudsyncd server tunnel setup
```

`setup` 会读取 `cloudflared-config.yml` 里的 `tunnel` 和第一个 `ingress.hostname`，然后依次执行：

- `cloudflared tunnel --config cloudflared-config.yml ingress validate`
- `cloudflared tunnel route dns <tunnel> <hostname>`

`setup` 只负责配置校验和 DNS 绑定，不会默认启动 tunnel。需要一键完成 setup 后立刻后台启动 tunnel 时，使用：

```bash
cloudsyncd server tunnel setup --start
```

`cloudsyncd server tunnel setup --tunnel` 也会按 `--start` 处理，保留这个别名是为了兼容 `server start --tunnel` 的用法直觉。

如果只想验证本地 ingress 配置：

```bash
cloudsyncd server tunnel validate
```

如果只想单独绑定 DNS hostname：

```bash
cloudsyncd server tunnel route-dns sync.example.com
```

这会执行 `cloudflared tunnel route dns <tunnel-name> <hostname>`，其中 tunnel 名称默认是 `sync`，可用 `--name <tunnel-name>` 覆盖。

日常启动服务和隧道：

```bash
cloudsyncd server start --tunnel
```

或服务已运行时单独启动隧道：

```bash
cloudsyncd server tunnel start
```

`tunnel start` 会在后台运行 `cloudflared`，把日志写到 `/tmp/cloudflared-sync.log`，并写入 pidfile，方便之后停止。

停止由 CLI 启动或记录 pidfile 的隧道：

```bash
cloudsyncd server tunnel stop
```

默认 pidfile 是 `/tmp/cloudflared-sync.pid`。如果没有找到 pidfile，`stop` 会返回成功并提示当前没有 CLI 托管的 tunnel。若启动时使用了自定义 tunnel 名称或 pidfile，停止时也传同样参数：

```bash
cloudsyncd server tunnel stop --name <tunnel-name>
cloudsyncd server tunnel stop --pidfile /path/to/cloudflared.pid
```

`--config <file>` 可指定 Tunnel 配置文件，默认是当前仓库的 `cloudflared-config.yml`。`WITH_TUNNEL=1 ./start.sh` 仍可作为兼容启动方式。

迁移到其他机器或域名时，需要重新创建 Cloudflare Tunnel，更新本地 `cloudflared-config.yml`，并重新执行 `cloudsyncd server tunnel route-dns <hostname>`。

没有固定域名时，可以临时使用：

```bash
cloudflared tunnel --url http://127.0.0.1:21891
```

### 远程访问 502 排障

公网 502 多数不是 DNS 绑定问题，而是 tunnel 后面的本机 origin 没有响应。`cloudflared` 正常运行时，如果 `127.0.0.1:21891` 没有 Node 服务监听，日志会出现 `connect: connection refused`，Cloudflare 会返回 502。

按下面顺序检查：

```bash
# 1. 本机 origin 是否运行
lsof -nP -iTCP:21891 -sTCP:LISTEN
curl -i http://127.0.0.1:21891/api/status

# 2. tunnel 是否运行
ps -ef | rg cloudflared
tail -n 80 /tmp/cloudflared-sync.log

# 3. 只缺 Node 服务时启动分享端
cloudsyncd server start

# 4. 需要同时启动服务和 tunnel 时使用
cloudsyncd server start --tunnel

# 5. 复测公网状态
curl -i https://<your-sync-hostname>/api/status
```

判断方式：

- 本机 `/api/status` 失败，公网 502：先启动 `cloudsyncd server start`。
- 本机 `/api/status` 成功，公网仍 502：看 `/tmp/cloudflared-sync.log` 和 `cloudsyncd server tunnel validate`。
- `cloudsyncd server tunnel start` 只启动 tunnel，不会启动 Node 服务；完整日常启动优先用 `cloudsyncd server start --tunnel`。

## 安全边界

- `data/state.json` 含主密钥和管理 Token，`data/` 必须保持忽略
- `shared/` 是运行态共享目录，内容会对已配对设备可见，必须保持忽略
- 浏览器客户端会把主密钥保存在 IndexedDB
- 所有已配对设备共享同一个主密钥；主密钥轮换会让全部设备重新配对
- Cloudflare Tunnel 只提供入口转发，不等价于应用层访问控制；需要额外身份门禁时，在 Cloudflare Zero Trust 中配置 Access

更多检查项见 [OPEN_SOURCE_AUDIT.md](./OPEN_SOURCE_AUDIT.md)。

## 发布检查

```bash
git status --short
git ls-files
```

发布或推送前确认：

- `data/` 未被提交
- `shared/` 中没有运行态载荷被提交
- `.env`、Cloudflare 凭证、日志、下载缓存未被提交
- 如需公开仓库，先移除或模板化私有域名、隧道 UUID、绝对路径和个人部署信息

## 已知限制

- 没有用户 / 角色系统，只有设备级配对和撤销
- 没有单文件或单设备 ACL，配对设备可访问 `shared/` 下的所有非隐藏文件
- 文本消息只保存在服务进程内存中，重启会丢失
- 当前仓库不再内置 Python 自动下载客户端
