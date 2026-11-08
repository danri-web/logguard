# LogGuard

基于 Win32 事件日志 API（`winevt`）的 Windows 安全日志分析终端工具，C99 实现，无第三方依赖。

支持两种数据源：**本机 Security 通道**（实时）和 **导出的 `.evtx` 文件**（离线，不需要管理员）。
交互菜单与命令行批处理两种用法，查询结果可导出为 CSV、输出统计面板，或生成单文件 HTML 报告。

> 读取本机 Security 通道需要管理员权限；分析 `.evtx` 文件不需要。
> 程序以 `asInvoker` 启动，不会强制弹 UAC；在非管理员环境下会给出提示。

---

## 功能

### 分析规则

| 菜单 | 功能 | 判定逻辑 |
|---|---|---|
| 1 | 浏览全部登录日志 | 最近 20 条 4624 / 4625 |
| 2 | 登录失败检测 | `EventID == 4625` |
| 3 | 管理员登录检测 | `EventID == 4625` 且账户为 `admin`（忽略大小写，兼容 `DOMAIN\admin`） |
| 4 | 高频 IP 爆破检测 | 同一源 IP 失败次数 ≥ 3；`-` 占位 IP 不参与聚合 |
| 5 | 凌晨异常登录检测 | `EventID == 4624` 且本地时间在 00:00–05:59 |
| 6 | 系统特权分配监控 | `EventID == 4672`（防提权） |
| 7 | 隐蔽后门账号监控 | `EventID == 4720`（防留后门） |
| 8 | 切换数据源 | 在本机 Security 通道与 `.evtx` 文件之间切换 |
| 9 | 统计面板 | 事件分布、Top 源 IP、Top 用户名、按小时直方图 |
| 10 | 导出 HTML 报告 | 单文件（内嵌 CSS），统计图 + 记录明细 |
| 11 | 安全事件总览 | 只取 4624 / 4625 / 4672 / 4720 四类审计事件 |

每条记录展示：EventId、时间、用户名、LogonType、描述、源 IP、进程名。
查询结束后可选择导出 CSV（带 UTF-8 BOM，Excel 直接打开不乱码）。

### 统计面板

菜单 9 或 `--stats` 输出数据总览，四块内容：

```text
  [事件分布]
    4625  登录失败  5 条  41.7%  ####################
    4624  登录成功  4 条  33.3%  ################
  [Top 源 IP]
    1. 203.0.113.7  3 次  ########################
  [Top 用户名]
    1. Danri  5 次  ########################
  [按小时直方图]
    02 时 | #################################### 4  <- 峰值
```

统计口径：

- 样本是当前数据源读到的记录（受 `--limit` / 菜单默认条数限制，最多 1024 条）。
- 不带 `--filter` 时读全部事件（XPath `*`），所以分布里会出现 4624/4625/4672/4720 以外的事件 ID；带 `--filter` 时只统计该规则命中的记录。
- 只想要安全事件：加 `--filter security`（= 4624/4625/4672/4720 四类），菜单 11 同效。
  如果文件其实不是 Security 通道，统计面板会提示「样本里四类事件不足一半」，因为
  Application/System 里存在同号事件（如 EventSystem 的 4625）。
- 事件分布按次数降序，次数相同按 EventID 升序；只展开前 8 种，其余合并成一行。
- 源 IP 排除空串与 `-`（本机登录等没有来源的场景）；用户名去掉 `DOMAIN\` 前缀，并按 ASCII 大小写无关聚合。
- 直方图按本地时间分 24 个桶，时间字段无法解析的记录单独计数，不当成 0 点；峰值并列时取较小的小时。

### HTML 报告

菜单 10 或 `--html <路径>` 生成**单文件**报告：CSS 内嵌、无外部资源、无 JavaScript，双击就能打开，也能直接发给别人。

```powershell
.\LogGuard.exe --file Security.evtx --html report.html
.\LogGuard.exe --file Security.evtx --filter failed --html failed.html
```

内容：汇总行（总数 / 事件种类 / 时间解析情况）、事件分布横条、Top 源 IP、Top 用户名、
按小时柱状图（峰值标红）、记录明细表（本次读到的全部样本，最多 1024 行）。
页面跟随系统深色模式；日志里的 `<` `&` `"` 等字符会转义，不会破坏页面结构。

### 命令行批处理

不进入菜单，执行完直接退出，适合脚本、批量分析和 CI：

```powershell
.\LogGuard.exe --file Security.evtx --filter failed --limit 200
.\LogGuard.exe --file Security.evtx --filter brute --export report.csv
.\LogGuard.exe --file Security.evtx --stats
```

| 选项 | 说明 |
|---|---|
| `--file <路径>` | 分析 `.evtx` 文件；不指定则读本机 Security 通道 |
| `--filter <规则>` | `all` `failed` `admin` `brute` `night` `privilege` `created` `security`，也可写规则编号 `1-7`；`security` = 四类审计事件 |
| `--limit <条数>` | 最多读取多少条，1–1024，默认按规则 |
| `--export <路径>` | 把结果导出为 CSV（支持中文路径） |
| `--stats` | 输出统计面板；可与 `--filter` 组合，与 `--export` 同用时导出统计所依据的原始记录 |
| `--html <路径>` | 生成单文件 HTML 报告（支持中文路径）；可与 `--filter`、`--stats` 组合 |
| `--since <时间>` | 只看该时间之后的事件（本地时间，`YYYY-MM-DD` / `YYYY-MM-DD HH:MM[:SS]`） |
| `--until <时间>` | 只看该时间之前的事件；可与 `--since` 组合成一个区间 |
| `--whitelist <路径>` | 白名单文件：每行 `ip <地址>` 或 `user <账户>`，`#` 开头是注释；命中的记录在筛选/统计/报告/导出之前剔除 |
| `--no-color` | 关闭 ANSI 颜色 |
| `-h, --help` | 显示帮助 |
| `-V, --version` | 显示版本号 |

退出码：`0` 成功，`1` 参数错误，`2` 读取失败，`3` 写文件失败（CSV / HTML）。

---

## 目录结构

```text
LogGuard/
├── CMakeLists.txt          # 构建 LogGuard 与 7 个测试目标
├── README.md
├── CHANGELOG.md
├── LICENSE                 # MIT
├── app.manifest            # asInvoker
├── app.rc                  # 将 manifest 嵌入 exe
│
├── include/
│   ├── log_entry.h         # LogEntry 结构体与字段长度常量
│   ├── log_reader.h        # 通道 / .evtx 文件读取接口
│   ├── xml_parser.h        # 从事件 XML 中提取字段
│   ├── filter.h            # 筛选谓词与 FilterFunc
│   ├── stats.h             # 统计面板的数据结构与聚合接口
│   ├── report.h            # HTML 报告接口（ReportMeta / Report_WriteHtml）
│   ├── export.h            # CSV 导出接口
│   ├── cli.h               # 命令行参数解析
│   ├── daterange.h         # --since/--until：本地时间 → UTC FILETIME → XPath
│   ├── whitelist.h         # 白名单规则与匹配
│   ├── version.h           # 版本号
│   └── ui.h                # 菜单、打印、MenuItem
│
├── src/
│   ├── main.c              # 双入口（交互 / 批处理）、爆破聚合、调度
│   ├── log_reader.c        # EvtQuery / EvtNext / EvtRender
│   ├── xml_parser.c        # 解析 <Data>、<EventID>、时间字段
│   ├── filter.c            # 7 个过滤函数 + 小时/账户名公共解析
│   ├── stats.c             # 事件分布、Top 排名、按小时直方图
│   ├── report.c            # 单文件 HTML 报告（内嵌 CSS、转义、柱状图）
│   ├── export.c            # CSV 写入（BOM、转义、公式注入防护）
│   ├── cli.c               # 参数解析、帮助文本
│   ├── daterange.c         # 时间解析、ISO 8601 格式化、XPath 拼装
│   ├── whitelist.c         # 白名单文件解析与过滤
│   └── ui.c                # 菜单、表头、单条打印、统计面板
│
└── tests/
    ├── test_filter.c       # 过滤器单元测试
    ├── test_cli.c          # 命令行参数解析测试
    ├── test_stats.c        # 统计聚合测试
    ├── test_report.c       # HTML 报告测试（转义、结构、空样本）
    ├── test_xml.c          # XML 解析器测试
    ├── test_daterange.c    # 时间范围与 XPath 拼装测试
    └── test_whitelist.c    # 白名单解析与匹配测试
```

---

## 环境要求

- Windows Vista 及以上（`winevt` API 自 Vista 起提供）
- 编译器：MinGW-w64（GCC 8+）或 MSVC 2015+
- CMake 3.10+（可选，直接 gcc 也能构建）
- 本机 Security 通道需要管理员；离线 `.evtx` 模式不需要

---

## 构建

### CMake（MinGW）

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
ctest --test-dir build --output-on-failure
```

### CMake（MSVC）

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### 直接 gcc

下面的 `windres` / `gcc` 假定 MinGW 的 `bin` 目录已经在 `PATH` 中。

```powershell
windres app.rc -o app.o
gcc -std=c99 -Wall -Wextra -Iinclude `
  src\main.c src\log_reader.c src\xml_parser.c src\filter.c src\ui.c src\stats.c src\report.c src\export.c src\cli.c `
  src\daterange.c src\whitelist.c `
  app.o -o LogGuard.exe -lwevtapi -lshell32
```

> `export.c`、`cli.c`、`stats.c`、`report.c` 都是必需源文件；`shell32` 用于 `CommandLineToArgvW`。

### 单元测试

```powershell
gcc -std=c99 -Wall -Wextra -Iinclude tests\test_filter.c src\filter.c -o test_filter.exe
gcc -std=c99 -Wall -Wextra -Iinclude tests\test_cli.c src\cli.c -o test_cli.exe
gcc -std=c99 -Wall -Wextra -Iinclude tests\test_xml.c src\xml_parser.c -o test_xml.exe
gcc -std=c99 -Wall -Wextra -Iinclude tests\test_stats.c src\stats.c src\filter.c -o test_stats.exe
gcc -std=c99 -Wall -Wextra -Iinclude tests\test_report.c src\report.c src\stats.c src\filter.c -o test_report.exe
gcc -std=c99 -Wall -Wextra -Iinclude tests\test_daterange.c src\daterange.c -o test_daterange.exe
gcc -std=c99 -Wall -Wextra -Iinclude tests\test_whitelist.c src\whitelist.c src\filter.c -o test_whitelist.exe
```

共 344 条断言（58 filter + 86 cli + 32 xml + 73 stats + 34 report + 33 daterange + 28 whitelist）。覆盖：8 个过滤器与边界、
命令行参数、XML 字段解析（含 `<EventID Qualifiers="...">` 兼容、Provider、UTF-8 截断）、
统计聚合（排序、并列、Top 上限、`-` 排除、账户大小写聚合、时间解析失败）、
HTML 报告（结构完整、深色模式、脚本注入被转义、空样本、临时文件已清理）、
时间范围（闰年/非法日期/ISO 8601/XPath 拼装）、白名单（注释、大小写、域前缀、上限）。

> **控制台编码**：程序输出 UTF-8。Windows PowerShell 5.1 默认按控制台代码页（936/GBK）
> 解码子进程输出，中文会显示成乱码。先在会话里执行
> `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`（写进 `$PROFILE` 可永久生效）；
> `chcp 65001` 单独在 5.1 里不够。测试程序在 Windows 下会自己把控制台切到 65001，
> 这一步只对 cmd / Windows Terminal 直接运行生效。

---

## 运行

### 交互模式

```powershell
.\LogGuard.exe
```

菜单 8 可以输入 `.evtx` 文件路径切换数据源；输入 `-` 切回本机 Security。
菜单 9 打印统计面板，菜单 10 在当前目录生成 `LogGuard_Report.html`。

### 离线分析

先用管理员终端导出 Security 日志，之后分析不再需要管理员：

```powershell
wevtutil epl Security Security.evtx
.\LogGuard.exe --file Security.evtx --filter failed --limit 200
.\LogGuard.exe --file Security.evtx --html Security-report.html
```

> `wevtutil epl` **不会自动建目录**：目标路径的父目录必须已存在，否则报
> `The system cannot find the path specified`。也可以直接导到当前目录（如上）。

### 非管理员时的提示

读取本机 Security 会失败，程序会显示真实错误码，例如：

```text
[错误] 无法读取 Security 通道！错误码 5：拒绝访问。（该通道需要管理员权限）
```

此时可改用 `--file`，或右键“以管理员身份运行”。

---

## 数据来源与字段映射

日志通过 `EvtQuery(NULL, target, xpath, flags)` 查询：

- 本机通道：`flags = EvtQueryChannelPath | EvtQueryReverseDirection`
- `.evtx` 文件：`flags = EvtQueryFilePath | EvtQueryReverseDirection`

XPath 示例：

```text
*[System[(EventID=4624 or EventID=4625)]]
```

事件经 `EvtRender` 渲染为 XML 后，从 `<EventData>` 中提取：

| LogEntry 字段 | XML 中的 Data Name | 备注 |
|---|---|---|
| `eventId` | `System/EventID` | 兼容带 `Qualifiers` 属性的写法 |
| `dateAndTime` | `System/TimeCreated@SystemTime` | UTC 转本地时间字符串 |
| `userName` | `TargetUserName` | 缺失时回退到 `SubjectUserName` |
| `logOnType` | `LogonType` | 整数 |
| `sourceIP` | `IpAddress` | 可能为 `-` 或 IPv6 |
| `processName` | `ProcessName` | 部分事件无此字段 |
| `description` | — | 按 EventId + LogonType 本地生成 |

> `description` 不使用系统消息文件还原，因此不会显示“账户已锁定”这类
> 由具体失败原因生成的文本。

---

## 设计要点

- **数据源抽象**：`ReadLogs(target, isFile, ...)` 用同一个查询流程处理通道与文件，
  上层的筛选、聚合、导出不需要关心日志从哪来。
- **双入口**：无参数进入交互菜单；带 `--file/--filter/...` 进入批处理，便于脚本化。
- **分层**：读取（`log_reader`）、解析（`xml_parser`）、筛选（`filter`）、
  导出（`export`）、参数（`cli`）、界面（`ui`）互不依赖，`main.c` 只做调度。
- **表驱动菜单**：新增规则只需在 `g_menuList` 加一行并实现对应 `FilterFunc`。
- **缓冲区安全**：`EvtRender` 先取大小再分配；描述文本按 UTF-8 字符边界截断。
- **时区正确**：`SystemTimeToTzSpecificLocalTime` 按系统时区/夏令时转换。
- **宽字符路径**：`.evtx` 与 CSV 路径都用宽字符 API，支持中文路径。
- **CSV 安全**：以 `=` `+` `-` `@` 开头的字段加 `'` 前缀，防止 Excel 公式注入；
  写完检查 `ferror`，避免把失败当成功。
- **权限显式化**：manifest 使用 `asInvoker`，运行期检测是否提升；读取失败显示
  Windows 错误码与系统描述。
- **统计与界面分离**：`stats.c` 只接收 `LogEntry` 数组、返回 `StatsSummary`，不依赖 Win32，
  排序与聚合规则因此在 `test_stats.c` 里可以直接断言；排版留在 `ui.c`。
- **报告即数据**：`report.c` 只往 `FILE*` 写 HTML，不碰 Win32 文件 API；打开文件的逻辑留在
  `main.c`（宽字符路径），于是报告内容可以在 `test_report.c` 里用 `tmpfile()` 断言。
- **HTML 安全**：所有日志字段经 `& < > " '` 转义后再进页面；报告不引用任何外部脚本或样式，
  即使日志里有 `<script>` 也只会显示成文本。

---

## 已知限制

- 仅支持本机通道与本地 `.evtx` 文件，不支持远程主机。
- 没有实时订阅（`EvtSubscribe`），不会像 `tail -f` 一样滚动。
- `description` 为本地生成的简短文本，非 Windows 消息文件原文。
- `.evtx` 中缺少 `TargetUserName` / `IpAddress` 等字段的事件，对应列会为空。
- `--limit` 上限 1024，受内存中的日志数组限制。
- 统计面板的样本同样最多 1024 条；直方图按本地时间，时间字段格式异常时不计入。
- HTML 报告同样最多 1024 行明细；图表是纯 CSS，没有交互筛选和导出图片。
- 事件分布的中文名只覆盖 4624/4625/4672/4720，其余 EventID 显示为“其它”。
- 事件按 EventID 判定；逐条模式下能读到 `<Provider>` 时会额外要求 Provider 名里带
  `Security-Auditing`（Application/System 的同号事件因此被排除）。**统计面板与 HTML 报告不套这一层**：
  它们仍按 XPath 命中的样本统计，所以 `--filter security --stats` 在非 Security 日志上仍可能算进同号事件。
  要严格的安全日志，请分析管理员导出的 `Security.evtx`。
- `--since` / `--until` 是**本地时间**，允许 `YYYY-MM-DD` 或 `YYYY-MM-DD HH:MM[:SS]`；秒以下和时区后缀不支持。
- `--whitelist` 只做精确匹配（不做 CIDR / 通配符）；账户名会去掉 `DOMAIN\` 前缀后比较，大小写无关。
  它在读入之后、筛选之前生效，因此面板和报告看到的是剔除后的样本。
- 路径上限 511 个宽字符。
- CSV 防公式注入会给以 `=`、`+`、`-`、`@` 开头的字段加 `'` 前缀（单独的 `-` 除外）。

---

## 参考

- [Windows Event Log API (winevt.h)](https://learn.microsoft.com/windows/win32/api/winevt/)
- [EvtQuery](https://learn.microsoft.com/windows/win32/api/winevt/nf-winevt-evtquery)
- [EvtRender](https://learn.microsoft.com/windows/win32/api/winevt/nf-winevt-evtrender)
- [4624 / 4625 事件说明](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)

---

## 许可证

[MIT](LICENSE)
