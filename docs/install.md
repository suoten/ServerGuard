# 安装指南

## 系统要求

- Go 1.26+
- Node.js 18+（仅Web面板构建需要）
- SQLite 3.35+（单机模式）或 PostgreSQL 14+（企业模式）

## 从源码构建

```bash
# 克隆仓库
git clone https://github.com/suoten/serverguard.git
cd serverguard

# 构建全部组件
make build

# 或分别构建
make build-agent    # Agent守护进程
make build-hub      # Hub面板后端
make build-cli      # sgctl命令行工具
make build-web      # Web前端
```

## 安装

### Linux

```bash
# 安装Agent
sudo cp bin/serverguard-agent /usr/local/bin/
sudo cp deploy/serverguard-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable serverguard-agent
sudo systemctl start serverguard-agent

# 安装Hub（可选）
sudo cp bin/serverguard-hub /usr/local/bin/
sudo cp deploy/serverguard-hub.service /etc/systemd/system/
sudo systemctl enable serverguard-hub
sudo systemctl start serverguard-hub
```

### Windows

```cmd
# 以管理员身份运行
copy bin\serverguard-agent.exe C:\Program Files\ServerGuard\
# 注册为Windows服务
sc create ServerGuard binPath= "C:\Program Files\ServerGuard\serverguard-agent.exe -config C:\ProgramData\ServerGuard\agent.yaml"
sc start ServerGuard
```

### Docker

```bash
docker-compose up -d
```

## 验证安装

```bash
sgctl status
sgctl doctor
```

## 卸载

### Linux
```bash
sudo systemctl stop serverguard-agent
sudo systemctl disable serverguard-agent
sudo rm /etc/systemd/system/serverguard-agent.service
sudo rm /usr/local/bin/serverguard-agent
```

### Windows
```cmd
sc stop ServerGuard
sc delete ServerGuard
del "C:\Program Files\ServerGuard\serverguard-agent.exe"
```