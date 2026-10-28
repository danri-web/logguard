# LogGuard

基于 Win32 事件日志 API（`winevt`）的 Windows 安全日志分析终端工具，C99 实现，无第三方依赖。

读取本机 **Security** 通道中的登录与账户事件，按表驱动菜单筛选，在终端以卡片形式展示；
支持按源 IP 聚合的暴力破解检测，并可将查询结果导出为 CSV。

> 需要管理员权限（Security 通道受系统保护）。程序通过 manifest 声明
> `requireAdministrator`，启动时会自动触发 UAC。

---

## 功能

| 菜单 | 功能 | 判定逻辑 |
|---|---|---|
| 1 | 浏览全部登录日志 | 最近 20 条 4624 / 4625 |
| 2 | 登录失败检测 | `EventID == 4625` |
| 3 | 管理员登录检测 | `EventID == 4625` 且账户为 `admin`（忽略大小写，兼容 `DOMAIN\admin`） |
| 4 | 高频 IP 爆破检测 | 最近 500 条中同一源 IP 失败次数 ≥ 3；`-` 占位 IP 不参与聚合 |
| 5 | 凌晨异常登录检测 | `EventID == 4624` 且本地时间在 00:00–05:59 |
| 6 | 系统特权分配监控 | `EventID == 4672`（防提权） |
| 7 | 隐蔽后门账号监控 | `EventID == 4720`（防留后门） |

每条记录展示：EventId、时间、用户名、LogonType、描述、源 IP、进程名。
查询结束后可选择导出 CSV（带 UTF-8 BOM，Excel 直接打开不乱码）。

---

## 目录结构

```text
LogGuard/
├── CMakeLists.txt          # 构建 LogGuard 与 test_filter 两个目标
├── README.md
├── LICENSE                 # MIT
├── app.manifest            # 声明 requireAdministrator
├── app.rc                  # 将 manifest 嵌入 exe
│
├── include/
│   ├── log_entry.h         # LogEntry 结构体与字段长度常量
│   ├── log_reader.h        # 读取 Security 日志的对外接口
│   ├── xml_parser.h        # 从事件 XML 中提取字段
│   ├── filter.h            # 筛选谓词与 FilterFunc
│   ├── export.h            # CSV 导出接口
│   └── ui.h                # 菜单、打印、MenuItem
│
├── src/
│   ├── main.c              # 主循环、表驱动菜单、爆破聚合、调度
│   ├── log_reader.c        # EvtQuery / EvtNext / EvtRender
│   ├── xml_parser.c        # 解析 <Data Name="..."> 与时间字段
│   ├── filter.c            # 7 个过滤函数
│   ├── export.c            # CSV 写入（BOM、转义、公式注入防护）
│   └── ui.c                # 菜单、表头、单条打印、汇总
│
└── tests/
    └── test_filter.c       # 过滤器单元测试（不依赖 Windows API）
```

---

## 环境要求

- Windows Vista 及以上（`winevt` API 自 Vista 起提供）
- 编译器：MinGW-w64（GCC 8+）或 MSVC 2015+
- CMake 3.10+（可选，直接 gcc 也能构建）
- **运行需要管理员权限**，否则无法打开 Security 通道

---

## 构建

### CMake（MinGW）

```bat
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
ctest --test-dir build --output-on-failure
```

### CMake（MSVC）

```bat
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

生成物：`build\LogGuard.exe`（manifest 已嵌入，双击即触发 UAC）。

### 直接 gcc

```bat
windres app.rc -o app.o
gcc -std=c99 -Wall -Wextra -Iinclude ^
  src\main.c src\log_reader.c src\xml_parser.c src\filter.c src\ui.c src\export.c ^
  app.o -o LogGuard.exe -lwevtapi
```

> `export.c` 是必需源文件（`main.c` 会调用 `ExportToCsv`），漏掉会在链接时报
> `undefined reference`。

### 单元测试

```bat
gcc -std=c99 -Wall -Wextra -Iinclude tests\test_filter.c src\filter.c -o test_filter.exe
test_filter.exe
```

覆盖 7 个过滤器，以及空时间、`-` 源 IP、`DOMAIN\admin`、大小写等边界用例。

---

## 运行

```bat
LogGuard.exe
```

启动时 Windows 弹出 UAC 提示，确认后进入主菜单。
若未以管理员身份运行，程序会显示真实错误码与系统描述，例如：

```text
[错误] 无法读取 Security 日志！错误码 5：拒绝访问。（该通道需要管理员权限）
```

---

## 数据来源与字段映射

日志通过 `EvtQuery(NULL, L"Security", xpath, ...)` 查询，XPath 示例：

```text
*[System[(EventID=4624 or EventID=4625)]]
```

事件经 `EvtRender` 渲染为 XML 后，从 `<EventData>` 中提取：

| LogEntry 字段 | XML 中的 Data Name | 备注 |
|---|---|---|
| `eventId` | `System/EventID` | 整数 |
| `dateAndTime` | `System/TimeCreated@SystemTime` | UTC 转本地时间字符串 |
| `userName` | `TargetUserName` | 缺失时回退到 `SubjectUserName` |
| `logOnType` | `LogonType` | 整数 |
| `sourceIP` | `IpAddress` | 可能为 `-` 或 IPv6 |
| `processName` | `ProcessName` | 部分事件无此字段 |
| `description` | — | 按 EventId + LogonType 本地生成，未调用 `FormatMessage` |

> `description` 不使用系统消息文件还原，因此不会显示“账户已锁定”这类
> 由具体失败原因生成的文本。

---

## 设计要点

- **分层**：数据获取（`log_reader`）、XML 解析（`xml_parser`）、筛选（`filter`）、
  导出（`export`）、界面（`ui`）互不依赖，`main.c` 只做调度。
- **表驱动菜单**：新增功能只需在 `g_menuList` 加一行并实现对应 `FilterFunc`，
  菜单打印与主循环不需要改动。
- **筛选双阶段**：XPath 在查询阶段按 EventID 粗筛，`filter.c` 在内存中细筛
  （用户名、时间等）。
- **缓冲区安全**：`EvtRender` 先取所需大小再分配；字段拷入定长数组前限制长度；
  生成描述文本时按 UTF-8 字符边界截断，不会切出半个汉字。
- **时区正确**：使用 `SystemTimeToTzSpecificLocalTime` 按系统当前时区/夏令时
  规则转换，不硬编码 UTC+8。
- **CSV 安全**：以 `=` `+` `-` `@` 开头的字段加 `'` 前缀并按文本加引号，
  防止 Excel 公式注入；写完检查 `ferror`，避免把失败当成功。
- **权限显式化**：manifest 声明 `requireAdministrator`；读取失败时显示
  Windows 错误码与系统描述。

---

## 已知限制

- 仅读取本机 Security 通道，不支持远程主机或 `.evtx` 文件。
- `description` 为本地生成的简短文本，非 Windows 消息文件原文。
- 未做分页，一次读取上限由菜单项的 `maxRead` 控制。
- CSV 防公式注入会给以 `=`、`+`、`-`、`@` 开头的字段加 `'` 前缀（单独的 `-` 除外）。
- 宽字符处理：底层 API 使用 `wchar_t`，输出经 `WideCharToMultiByte` 转 UTF-8，
  控制台代码页设为 65001。

---

## 参考

- [Windows Event Log API (winevt.h)](https://learn.microsoft.com/windows/win32/api/winevt/)
- [EvtQuery](https://learn.microsoft.com/windows/win32/api/winevt/nf-winevt-evtquery)
- [EvtRender](https://learn.microsoft.com/windows/win32/api/winevt/nf-winevt-evtrender)
- [4624 / 4625 事件说明](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)

---

## 许可证

[MIT](LICENSE)
