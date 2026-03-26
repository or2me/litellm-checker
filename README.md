# litellm-checker

基于 [lucubrator/litellm-check](https://github.com/lucubrator/litellm-check) 二次开发的 `litellm` 安全检测工具。

当前版本额外增加了两类能力：

- 支持通过 Everything 搜索结果页 URL 追加扫描目标
- 命令行输出、提示和文档全面中文化

核心原则只有一条：**只读文件系统，不执行任何可疑 Python 解释器**。工具会直接检查 `site-packages`、`dist-info`、`RECORD`、`.pth` 等文件痕迹，不会调用目标环境里的 `python`、`pip` 或入口脚本。

---

## 为什么必须只读文件系统

`litellm` 的部分版本曾出现恶意代码投递问题：

| 版本 | 恶意载荷位置 | 触发条件 |
|---|---|---|
| `1.82.7` | `litellm/proxy/proxy_server.py` | `import litellm.proxy` |
| `1.82.8` | `site-packages/litellm_init.pth` | **任意** Python 启动 |

如果你直接在受污染环境里运行 `python`、`pip` 或其它 Python 入口，可能会立刻执行恶意代码。这个项目的目标就是规避这类风险。

参考事件说明：
[BerriAI/litellm#24512](https://github.com/BerriAI/litellm/issues/24512)

---

## 当前能力

- 中文 CLI 提示和中文扫描结果
- 只读文件系统检测，不执行被检查环境
- 支持单路径扫描和递归扫描
- 支持自动发现全局 Python 安装
- 支持实时输出扫描结果
- 扫描结束后自动生成 HTML 报告
- 支持通过 Everything HTTP 搜索结果页追加扫描目标
- 对重复路径按真实路径去重，不会重复扫描同一个 `site-packages`

---

## 快速开始

建议使用**可信的系统 Python**运行本工具，不要在待排查的虚拟环境内直接执行。

Windows 上更稳妥的方式是：

```bash
py -3 -S safe_litellm_detector.py C:\path\to\project --recursive
py -3 -S audit_litellm.py
```

Linux / macOS 可以这样：

```bash
python3 safe_litellm_detector.py ~/work --recursive
python3 audit_litellm.py
```

说明：

- `-S` 会跳过 `site` 自动加载，能进一步减少启动时误碰异常环境的风险
- 工具本身只使用 Python 标准库

---

## 两个入口脚本

### `safe_litellm_detector.py`

适合“我已经知道大致要查哪里”的场景。它接受一个或多个路径，可以是：

- 虚拟环境根目录
- `site-packages` 目录
- 项目目录
- 更大的目录树（配合 `--recursive`）

示例：

```bash
python3 safe_litellm_detector.py /path/to/.venv
python3 safe_litellm_detector.py ~/projects/my-app --recursive
python3 safe_litellm_detector.py ~/code --recursive --json
python3 safe_litellm_detector.py ~ --recursive --no-global
python3 safe_litellm_detector.py C:\work --recursive --eve
```

注意：Everything 集成现在使用 `--eve` 参数，不再使用位置参数。

### `audit_litellm.py`

适合“先把常见位置全部扫一遍”的场景。它会自动扫描：

- `~/projects`
- `~/work`
- 用户目录下可发现的独立虚拟环境和 IDE 缓存环境
- 全局 Python 安装
- Windows 下的 `C:\ws` 和 `C:\ws_*`

示例：

```bash
python3 audit_litellm.py
python3 audit_litellm.py ~/src /mnt/shared-envs --json
python3 audit_litellm.py --strict-1827
python3 audit_litellm.py --eve
```

---

## `--eve` 模式

两个脚本都支持 `--eve`。

启用后，程序会提示你输入 Everything HTTP 搜索结果页地址，例如：

```text
http://127.0.0.1/?search=litellm
```

程序会自动：

1. 把该 URL 转成 Everything 的 JSON 输出模式
2. 提取搜索结果中的本地路径
3. 从结果中折叠出对应的 `site-packages` 目标
4. 与命令行原有扫描目标合并
5. 按真实路径去重，避免重复扫描

典型用法：

```bash
python3 safe_litellm_detector.py C:\repos --recursive --eve
python3 audit_litellm.py --eve
```

适用场景：

- 你已经在 Everything 里搜索了 `litellm`
- 想直接复用搜索结果，而不是再靠目录遍历慢慢找
- 想把 Everything 命中的路径和原有扫描范围合并起来

---

## 输出方式

### 1. 终端实时输出

在非 `--json`、非 `--quiet` 模式下，扫描是**边扫边打印**的，不需要等全部结束。

终端输出示例：

```text
目标: C:\demo\.venv
  ✘ C:\demo\.venv\Lib\site-packages
    状态: 疑似已被植入后门
    原因:
      - 版本=1.82.8
      - 存在 litellm_init.pth
      - RECORD 中提到了 litellm_init.pth
    版本: 1.82.8
    检测到 litellm_init.pth 后门文件
    RECORD 引用了 litellm_init.pth
```

### 2. JSON 输出

适合脚本集成、机器处理：

```bash
python3 safe_litellm_detector.py ~/work --recursive --json
python3 audit_litellm.py --json
```

JSON 中的 `classification` 仍然保持稳定英文值：

- `clean`
- `suspicious`
- `compromised-candidate`

### 3. HTML 报告

每次扫描结束后，都会在**当前运行目录**生成一个 HTML 报告文件。

文件名示例：

```text
litellm-check-report-20260326-153000.html
litellm-audit-report-20260326-153105.html
```

HTML 报告特点：

- 高风险结果排在最前面
- 可疑结果排在其次
- 正常结果排在最后
- 包含状态、目标路径、`site-packages`、版本、原因
- 包含扫描汇总

---

## 判定规则

| 判定值 | 含义 |
|---|---|
| `clean` | 没发现 `litellm` 痕迹 |
| `suspicious` | 发现 `litellm`，但没有高置信 IOC，或者元数据异常 |
| `compromised-candidate` | 命中了已知高风险 IOC |

### 当前检查的 IOC / 痕迹

| 文件或目录 | 作用 |
|---|---|
| `litellm/` | 包目录是否存在 |
| `litellm-*.dist-info/METADATA` | 提取版本信息 |
| `litellm-*.dist-info/PKG-INFO` | 备用版本信息 |
| `litellm-*.dist-info/RECORD` | 是否引用 `litellm_init.pth` |
| `litellm_init.pth` | 1.82.8 的高风险后门痕迹 |
| 多个 `dist-info` 目录 | 可能存在残留或冲突 |
| 缺失/损坏元数据 | 可疑状态 |

### 高风险条件

命中以下任一条件，会判定为 `compromised-candidate`：

- 版本是 `1.82.8`
- 存在 `litellm_init.pth`
- `RECORD` 中引用了 `litellm_init.pth`
- 开启 `--strict-1827` 且版本是 `1.82.7`

### 可疑条件

以下情况会判定为 `suspicious`：

- 版本是 `1.82.7`
- 元数据缺失或格式异常
- 存在多个 `dist-info` 目录
- 发现 `litellm` 包目录但没有对应 `dist-info`
- 发现了其它版本的 `litellm`

---

## 退出码

| 退出码 | 含义 |
|---|---|
| `0` | `clean` |
| `1` | `suspicious` |
| `2` | `compromised-candidate` |
| `3` | 运行错误 |

---

## CLI 参数

### `safe_litellm_detector.py`

```text
safe_litellm_detector.py [OPTIONS] TARGET [TARGET ...]
```

| 参数 | 说明 |
|---|---|
| `TARGET` | 要扫描的路径，可以传多个 |
| `--recursive` | 递归寻找目标下的 `site-packages` |
| `--no-global` | 配合 `--recursive` 时跳过全局 Python |
| `--json` | 输出 JSON |
| `--strict-1827` | 把 `1.82.7` 也按高风险处理 |
| `--quiet` | 不输出文本，只保留退出码 |
| `--eve` | 额外读取 Everything 搜索结果页并加入扫描 |

### `audit_litellm.py`

```text
audit_litellm.py [OPTIONS] [DIR ...]
```

| 参数 | 说明 |
|---|---|
| `DIR` | 额外扫描目录 |
| `--json` | 输出 JSON |
| `--strict-1827` | 把 `1.82.7` 也按高风险处理 |
| `--quiet` | 不输出文本，只保留退出码 |
| `--eve` | 额外读取 Everything 搜索结果页并加入扫描 |

---

## 适合什么场景

| 场景 | 推荐 |
|---|---|
| 先扫一遍常见目录 | `audit_litellm.py` |
| 明确知道要检查哪几个路径 | `safe_litellm_detector.py` |
| 想复用 Everything 的搜索结果 | 任一脚本加 `--eve` |
| 需要给其它系统消费结果 | 任一脚本加 `--json` |
| 只关心退出码 | 任一脚本加 `--quiet` |

---

## 架构概览

```text
safe_litellm_detector.py
├─ discover_site_packages()
├─ inspect_site_packages()
├─ classify()
├─ discover_global_site_packages()
├─ discover_everything_targets()
├─ format_report_text()
├─ format_report_json()
└─ format_report_html()

audit_litellm.py
├─ RepoVenvDiscovery
├─ StandaloneVenvDiscovery
├─ GlobalPythonDiscovery
├─ EverythingDiscovery
├─ Auditor
└─ write_audit_report_html()
```

---

## 测试

```bash
py -3 -S -m unittest test_detector.py test_audit.py
py -3 -S -m unittest test_detector.py
py -3 -S -m unittest test_audit.py
```

当前测试覆盖：

- 基础路径发现
- 版本提取
- RECORD 检查
- 分类逻辑
- Everything 路径提取
- HTML 排序
- 审计器去重
- 实时回调输出接线

---

## 运行要求

- Python 3.10+
- 仅依赖标准库
- 不调用目标环境子进程
- 支持 Windows、macOS、Linux
