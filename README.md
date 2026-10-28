# LogGuard

基于 Win32 事件日志 API（`winevt`）的 Windows 安全日志分析终端工具，C99 实现，无第三方依赖。

支持两种数据源：**本机 Security 通道**（实时）和 **导出的 `.evtx` 文件**（离线，不需要管理员）。
交互菜单与命令行批处理两种用法，查询结果可导出为 CSV。

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

每条记录展示：EventId、时间、用户名、LogonType、描述、源 IP、进程名。
查询结束后可选择导出 CSV（带 UTF-8 BOM，Excel 直接打开不乱码）。

### 命令行批处理

不进入菜单，执行完直接退出，适合脚本、批量分析和 CI：

```powershell
.\LogGuard.exe --file Security.evtx --filter failed --limit 200
.\LogGuard.exe --file Security.evtx --filter brute --export report.csv
```

| 选项 | 说明 |
|---|---|
| `--file <路径>` | 分析 `.evtx` 文件；不指定则读本机 Security 通道 |
| `--filter <规则>` | `all` `failed` `admin` `brute` `night` `privilege` `created`，也可写菜单编号 `1-7` |
| `--limit <条数>` | 最多读取多少条，1–1024，默认按规则 |
| `--export <路径>` | 把结果导出为 CSV（支持中文路径） |
| `--no-color` | 关闭 ANSI 颜色 |
| `-h, --help` | 显示帮助 |
| `-V, --version` | 显示版本号 |

退出码：`0` 成功，`1` 参数错误，`2` 读取失败，`3` 导出失败。

---

## 目录结构

```text
LogGuard/
├── CMakeLists.txt          # 构建 LogGuard 与 3 个测试目标
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
│   ├── export.h            # CSV 导出接口
│   ├── cli.h               # 命令行参数解析
│   ├── version.h           # 版本号
│   └── ui.h                # 菜单、打印、MenuItem
│
├── src/
│   ├── main.c              # 双入口（交互 / 批处理）、爆破聚合、调度
│   ├── log_reader.c        # EvtQuery / EvtNext / EvtRender
│   ├── xml_parser.c        # 解析 <Data>、<EventID>、时间字段
│   ├── filter.c            # 7 个过滤函数
│   ├── export.c            # CSV 写入（BOM、转义、公式注入防护）
│   ├── cli.c               # 参数解析、帮助文本
│   └── ui.c                # 菜单、表头、单条打印、汇总
│
└── tests/
    ├── test_filter.c       # 过滤器单元测试
    ├── test_cli.c          # 命令行参数解析测试
    └── test_xml.c          # XML 解析器测试
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
  src\main.c src\log_reader.c src\xml_parser.c src\filter.c src\ui.c src\export.c src\cli.c `
  app.o -o LogGuard.exe -lwevtapi -lshell32
```

> `export.c`、`cli.c` 都是必需源文件；`shell32` 用于 `CommandLineToArgvW`。

### 单元测试

```powershell
gcc -std=c99 -Wall -Wextra -Iinclude tests\test_filter.c src\filter.c -o test_filter.exe
gcc -std=c99 -Wall -Wextra -Iinclude tests\test_cli.c src\cli.c -o test_cli.exe
gcc -std=c99 -Wall -Wextra -Iinclude tests\test_xml.c src\xml_parser.c -o test_xml.exe
```

覆盖：7 个过滤器与边界、命令行参数、XML 字段解析（含 `<EventID Qualifiers="...">` 兼容与 UTF-8 截断）。

---

## 运行

### 交互模式

```powershell
.\LogGuard.exe
```

菜单 8 可以输入 `.evtx` 文件路径切换数据源；输入 `-` 切回本机 Security。

### 离线分析

先用管理员终端导出 Security 日志，之后分析不再需要管理员：

```powershell
wevtutil epl Security Security.evtx
.\LogGuard.exe --file Security.evtx --filter failed --limit 200
```

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

---

## 已知限制

- 仅支持本机通道与本地 `.evtx` 文件，不支持远程主机。
- 没有实时订阅（`EvtSubscribe`），不会像 `tail -f` 一样滚动。
- `description` 为本地生成的简短文本，非 Windows 消息文件原文。
- `.evtx` 中缺少 `TargetUserName` / `IpAddress` 等字段的事件，对应列会为空。
- `--limit` 上限 1024，受内存中的日志数组限制。
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
