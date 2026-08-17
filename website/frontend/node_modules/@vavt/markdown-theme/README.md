# markdown-theme

[md-editor-v3](https://github.com/imzbf/md-editor-v3)系列预览`markdown`内容主题。

| 主题名 | 来源 |
| --- | --- |
| default |  |
| vuepress |  |
| github |  |
| cyanosis | [juejin-markdown-theme-cyanosis](https://github.com/linxsbox/juejin-markdown-theme-cyanosis) |
| mk-cute | [juejin-markdown-theme-mk-cute](https://github.com/Jacky-Summer/juejin-markdown-theme-mk-cute) |
| smart-blue | [juejin-markdown-theme-smart-blue](https://github.com/cumt-robin/juejin-markdown-theme-smart-blue) |

> 样式不完全与原主题相同，仅部分参考。此仓库为编辑器默认主题库。如果您有优秀的主题，鼓励前往扩展库[md-editor-extension](https://github.com/imzbf/md-editor-extension)参与贡献。

## 安装

```shell
yarn add @vavt/markdown-theme
```

## 使用

引入单个主题（按需替换[name].css）

```js
import '@vavt/markdown-theme/default.css';
```

引入全部主题

```js
import '@vavt/markdown-theme/all.css';
```

> 不再支持在`>2.10.0`版本的编辑器中单独引入主题。

## 开发手册

目录解析

```
common                    # 公共样式目录
├── modules               # 模块样式目录
│   ├── admonition.scss   # 提示框样式
│   ├── code.scss         # 代码块样式
│   ├── figure.scss       # 图像样式
│   ├── heading.scss      # 标题样式
│   ├── hr.scss           # 分割线样式
│   ├── image.scss        # 图像样式
│   ├── katex.scss        # 数学公式样式
│   ├── link.scss         # 链接样式
│   ├── list.scss         # 列表样式
│   ├── mermaid.scss      # 流程图等样式
│   ├── paragraph.scss    # 段落样式
│   ├── quote.scss        # 引用样式
│   └── table.scss        # 表格样式
├── css-vars.scss         # CSS 变量定义
├── index.scss            # 公共样式入口
└── scss-vars.scss        # SCSS 变量定义
themes
├── all                   # 所有主题样式目录
    ├── index.scss        # 汇集所有主题样式入口，新增主题时需要在此处引入
├── default               # default 主题样式目录
    ├── modules           # 当前主题模块样式目录，与 common/modules 结构相同，用于覆盖公共样式
    ├── css-vars.scss     # 当前主题 CSS 变量定义，用于覆盖公共变量
    ├── index.scss        # 当前主题样式入口
    └── scss-var.scss     # SCSS 变量定义
├── cyanosis              # cyanosis 主题样式目录
├── github                # github 主题样式目录
├── mk-cute               # mk-cute 主题样式目录
├── smart-blue            # smart-blue 主题样式目录
└── vuepress              # vuepress 主题样式目录
```

1. 新增主题，可以以`themes/default`目录为模块，创建新的主题目录，并修改对应的样式文件。
2. 新增模块样式，可以在`common/modules`目录下创建对应的样式文件，并在`common/index.scss`中引入。同时需要在各主题的`modules`目录下创建对应的样式文件，用于覆盖公共样式。
3. 新增公共变量，可以在`common/scss-vars.scss`和`common/css-vars.scss`中添加变量定义。
4. 新增主题变量，可以在对应主题的`scss-vars.scss`和`css-vars.scss`中添加变量定义。
5. 新增主题后，需要在`themes/all/index.scss`中引入新的主题样式入口。
