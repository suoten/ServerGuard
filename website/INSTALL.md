# ServerGuard 官网安装说明

## 快速安装（单二进制）

### 方式 1：下载预编译二进制

```bash
# 1. 下载到当前目录
wget https://dl.serverguard.cn/website/serverguard-web-linux-amd64 -O serverguard-web
chmod +x serverguard-web

# 2. 创建数据目录
mkdir -p data/uploads

# 3. 运行
./serverguard-web
```

### 方式 2：从源码构建

```bash
# 1. 克隆仓库
git clone https://github.com/shuoteng/serverguard.git
cd serverguard/website

# 2. 构建（需要 Node.js + Go）
bash build.sh

# 3. 运行
cd backend
./serverguard-web  # 或 serverguard-web.exe (Windows)
```

### 方式 3：一键安装脚本（Linux）

```bash
curl -fsSL https://dl.serverguard.cn/website/install.sh | bash
```

## Nginx 反向代理配置

```nginx
server {
    listen 80;
    server_name sg.yourdomain.com;

    # 前端（SPA）
    location / {
        proxy_pass http://127.0.0.1:8422;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # 静态资源（可选：直接由 Nginx serve 可提升性能）
    location /assets/ {
        proxy_pass http://127.0.0.1:8422;
        proxy_cache_valid 200 7d;
        add_header Cache-Control "public, max-age=604800";
    }

    # API 接口
    location /api/ {
        proxy_pass http://127.0.0.1:8422;
        proxy_set_header Host $host;
    }
}
```

## 配置选项

环境变量：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SG_WEB_PORT` | `8422` | HTTP 监听端口 |
| `SG_WEB_DATA_DIR` | `./data` | 数据目录（数据库 + 上传文件） |

## 目录结构

```
serverguard-web          ← 单二进制文件
├── data/
│   ├── serverguard.db ← SQLite 数据库
│   └── uploads/        ← 上传的二进制文件
└── serverguard-web.service  ← systemd 配置（可选）
```

## 默认账号

- 用户名：`admin`
- 密码：`admin123`

⚠️ **请立即登录后台修改密码！**

## 管理

### 查看状态

```bash
./serverguard-web
```

### 后台管理

- 访问：`http://your-domain.com/admin`
- 登录：`admin` / `admin123`

### 版本发布（供 Agent 更新）

1. 登录后台
2. 进入"版本管理"
3. 上传新的 ServerGuard 二进制文件
4. 填写版本号（如 0.1.1）、SHA256、更新日志
5. 发布

Agent 端会自动检测到新版本并提示用户更新。

## 故障排查

### 端口被占用

```bash
# 查找占用 8422 端口的进程
lsof -i :8422

# 或修改端口
SG_WEB_PORT=8432 ./serverguard-web
```

### 数据库损坏

```bash
# 数据库会自动初始化，删除后重启即可重新创建
rm data/serverguard.db
./serverguard-web
```

### 查看日志

```bash
# 直接运行时输出到终端
./serverguard-web

# 或通过 systemd 查看
journalctl -u serverguard-website -f
```