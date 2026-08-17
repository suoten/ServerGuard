# ServerGuard 官网

> ServerGuard 产品官网 + 后台管理系统

## 目录结构

```
website/
├── frontend/           # Vue3 + Vite 前端（官网页面 + 管理后台）
│   ├── package.json
│   ├── vite.config.ts
│   ├── index.html
│   └── src/
│       ├── main.ts
│       ├── App.vue
│       ├── router/index.ts          # 路由配置
│       ├── styles/theme.css         # 全局样式
│       ├── composables/useAPI.ts    # API 封装
│       ├── components/
│       │   ├── DefaultLayout.vue    # 公共布局（Header + Footer）
│       │   ├── WebsiteHeader.vue    # 导航栏
│       │   └── WebsiteFooter.vue    # 页脚
│       └── views/
│           ├── Home.vue            # 首页（Hero + 功能 + 定价摘要 + FAQ）
│           ├── Pricing.vue         # 定价页（四档对比 + 地区切换）
│           ├── Download.vue        # 下载页
│           ├── Blog.vue            # 博客列表
│           ├── BlogPost.vue        # 博客详情
│           ├── Security.vue        # 安全公告
│           ├── About.vue           # 关于我们
│           ├── Docs.vue            # 文档入口
│           ├── NotFound.vue        # 404
│           └── admin/
│               ├── AdminLogin.vue       # 后台登录
│               ├── AdminLayout.vue      # 后台布局
│               ├── AdminDashboard.vue   # 仪表盘
│               ├── AdminContent.vue     # 网站内容编辑
│               ├── AdminPricing.vue     # 定价管理
│               ├── AdminVersions.vue    # 版本管理（上传/发布二进制）
│               ├── AdminBlog.vue         # 博客管理
│               └── AdminSecurity.vue     # 安全公告管理
│
├── backend/            # Go + Gin 后端 API
│   ├── go.mod
│   ├── main.go         # HTTP 服务入口
│   ├── store.go        # SQLite 数据层
│   ├── handlers.go     # API 处理器
│   └── auth.go         # JWT 认证 + bcrypt 密码
│
└── data/               # 运行时数据（自动创建）
    ├── serverguard.db  # SQLite 数据库
    └── uploads/        # 上传的二进制文件
```

## 快速开始

### 前端

```bash
cd website/frontend
npm install
npm run dev          # 开发服务器 http://localhost:3200
```

### 后端

```bash
cd website/backend
go mod tidy
go run .             # API 服务器 http://localhost:8422
```

默认管理员账号：`admin` / `admin123`（**请立即修改！**）

### 生产部署

```bash
# 1. 构建前端
cd website/frontend
npm run build        # 输出到 dist/

# 2. 构建后端
cd website/backend
go build -o serverguard-web .

# 3. 运行（自动 serve 前端 dist/）
SG_WEB_PORT=80 ./serverguard-web
```

## 核心功能

### 1. 版本更新机制

这是 Agent 自动检测更新的完整流程：

```
你在后台管理 → 版本管理 → 上传新版本二进制
  → 后端自动计算 SHA256，存入数据库
  → Agent 启动时调用 GET /api/v1/latest?channel=stable&os=linux&arch=amd64
  → 后端返回最新版本信息（版本号、下载URL、SHA256、更新日志）
  → Agent 对比版本号，发现 0.1.1 > 当前 0.1.0
  → Agent 面板提示用户"有新版本可用"
  → 用户点击升级 → Agent 下载二进制 → SHA256 校验 → 原子替换 → 重启
```

对应 Agent 端代码：`internal/agent/upgrader/upgrader.go` 中的 `CheckForUpdate()` 方法。

### 2. 免费转收费策略

在后台管理 → 定价管理页面：
- 每个版本可独立设置：启用/隐藏、价格、是否"即将上线"
- 前期：社区版免费，专业版可标记"限时免费"或"即将上线"
- 有用户基础后：修改价格、取消"即将上线"标记即可开始收费
- 所有修改实时生效，无需重新部署

### 3. 网站内容后台可编辑

在后台管理 → 网站内容页面，可编辑：
- 首页 Hero 区域（标题、副标题、安装命令）
- 功能特性列表（可增删）
- 统计数字（可增删）
- FAQ 列表（可增删）
- 用户证言
- 页脚信息

### 4. 完整的 CMS 功能

| 功能 | 说明 |
|------|------|
| 版本管理 | 上传二进制、自动计算 SHA256、版本号/渠道/更新日志/关键更新标记 |
| 博客管理 | Markdown 编写、草稿/发布、分类/作者/Slug |
| 安全公告 | CVE 编号、严重级别、影响版本、修复版本、详细描述 |
| 定价管理 | 四档版本、地区定价（CNY/USD）、功能列表、启用/隐藏 |
| 内容编辑 | 首页所有内容区块后台可编辑 |

## API 接口

### 公共 API

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/content` | 获取网站内容 |
| GET | `/api/v1/pricing` | 获取定价方案 |
| GET | `/api/v1/blog` | 博客列表 |
| GET | `/api/v1/blog/:slug` | 博客详情 |
| GET | `/api/v1/security` | 安全公告列表 |
| GET | `/api/v1/versions` | 版本列表 |
| GET | `/api/v1/latest` | **Agent 更新检查接口** |
| GET | `/api/v1/download/:id` | 下载版本二进制 |
| GET | `/api/v1/stats` | 公共统计 |

### Admin API（需 Bearer Token）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/admin/login` | 管理员登录 |
| GET/PUT | `/api/v1/admin/content` | 读取/编辑网站内容 |
| GET/PUT | `/api/v1/admin/pricing` | 读取/编辑定价 |
| GET | `/api/v1/admin/versions` | 所有版本 |
| POST | `/api/v1/admin/versions` | 上传新版本（multipart） |
| PUT/DELETE | `/api/v1/admin/versions/:id` | 修改/删除版本 |
| GET/POST | `/api/v1/admin/blog` | 博客列表/新建 |
| PUT/DELETE | `/api/v1/admin/blog/:id` | 修改/删除博客 |
| GET/POST | `/api/v1/admin/security` | 公告列表/新建 |
| PUT/DELETE | `/api/v1/admin/security/:id` | 修改/删除公告 |
| GET | `/api/v1/admin/stats` | 仪表盘统计 |

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SG_WEB_PORT` | `8422` | 后端监听端口 |
| `SG_WEB_DATA_DIR` | `./data` | 数据目录（SQLite + 上传文件） |

## 技术栈

- **前端**：Vue 3 + Vite + Element Plus + Pinia + Vue Router
- **后端**：Go + Gin + SQLite (modernc.org/sqlite, 纯 Go 无 CGO)
- **认证**：JWT (HS256) + bcrypt 密码哈希
- **部署**：单二进制（后端 serve 前端 dist/）
