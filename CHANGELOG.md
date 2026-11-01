# Changelog

## [3.2.3] - 2026-11-01

### Added

- 「安全事件总览」（菜单 11 / `--filter security`）：只统计 / 只列出
  4624 登录成功、4625 登录失败、4672 特权分配、4720 创建账户四类审计事件。
- 统计面板与 HTML 报告在「看全部事件」时做数据体检：样本里四类事件不足一半会提示
  “这个文件可能不是 Security 通道”，并给出 `--filter security` 建议。

### Notes

- `security` 只按 EventID 匹配，不校验 Provider：Application/System 通道里存在同号事件
  （例如 EventSystem 的 4625），要得到严格的安全日志请分析管理员导出的 `Security.evtx`。

## [3.2.2] - 2026-11-01

### Fixed

- `tests/test_report.c` 不再依赖 `tmpfile()`：部分 Windows 环境（`%TMP%` 不可写、
  受限沙箱、旧 msvcrt 把临时文件建在当前盘根目录）下 `tmpfile()` 直接返回 NULL，
  会让 28 条断言全部连坐失败。改为在当前目录写 `_test_report.tmp.html`，用完即删。

## [3.2.1] - 2026-11-01

### Fixed

- 测试程序在 Windows 控制台输出 UTF-8 中文时不再乱码：新增 `tests/console_utf8.h`，
  统一把控制台代码页切到 65001（对 cmd / Windows Terminal 直接运行生效）。
- README「单元测试」补上控制台编码说明：PowerShell 5.1 读子进程输出按控制台编码解码，
  需要在会话里设置 `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`；只改
  `chcp` 在 5.1 里不生效。

## [3.2.0] - 2026-11-01

### Added

- HTML 报告（菜单 10 / `--html <路径>`）：单文件、内嵌 CSS、无外部依赖；
  汇总行 + 事件分布横条 + Top 源 IP / Top 用户名 + 按小时柱状图（峰值标红）+ 记录明细表，
  跟随系统深色模式。
- `src/report.c` + `include/report.h`：纯 C99 渲染层，只往 `FILE*` 写，不碰 Win32；
  `tests/test_report.c`（33 条断言）覆盖文档结构、`& < > " '` 转义、空样本与非法参数。
- `Stats_EventName` 从 `ui.c` 移到 `stats.c`，面板与报告共用同一份 EventID 中文名。

### Changed

- `--stats` 与 `--html` 可以组合：一次查询同时打印面板并写报告；`--html` 单独使用时默认统计全部事件。
- `ExecuteQuery` 的输出选项收敛成 `OutputOptions`（CSV / HTML / 是否询问 / 统计模式）。
- 退出码 `3` 的含义从「导出失败」扩展为「写文件失败（CSV / HTML）」。

## [3.1.0] - 2026-11-01

### Added

- 统计面板（菜单 9 / `--stats`）：事件分布、Top 源 IP（前 5）、Top 用户名（前 5）、
  按小时直方图（24 桶），并标出峰值小时。
- `src/stats.c` + `include/stats.h`：纯 C99 聚合层，只吃 `LogEntry` 数组，不依赖 Win32；
  `tests/test_stats.c`（68 条断言）覆盖排序、并列、Top 上限、`-` 排除、账户大小写聚合、
  时间解析失败与输入不被修改。
- `filter.c` 公开 `Filter_ParseHour` / `Filter_AccountName`，供筛选与统计共用，
  避免两处各写一份小时/账户名解析。

### Changed

- `ExecuteQuery` 增加 `statsMode` 参数；统计模式下打印面板而不是逐条记录，
  导出仍然是统计所依据的原始记录。
- 统计默认读取全部事件（XPath `*`），带 `--filter` 时只统计该规则命中的记录。

## [3.0.0] - 2026-10-28

### Added

- 离线 `.evtx` 文件分析：`ReadLogs(target, isFile, ...)` 统一通道/文件两种数据源，
  交互菜单新增第 8 项「切换数据源」。
- 命令行批处理：`--file`、`--filter`、`--limit`、`--export`、`--no-color`、
  `--help`、`--version`；退出码 0/1/2/3。
- `tests/test_cli.c`（45 条断言）与 `tests/test_xml.c`（27 条断言），`ctest` 共 3 个目标。
- `include/version.h` 统一版本号。

### Changed

- CSV 导出改用宽字符路径（`_wfopen`），支持中文文件名。
- manifest 由 `requireAdministrator` 改为 `asInvoker`：离线分析不再强制 UAC；
  读取本机 Security 仍建议以管理员运行，并在启动时提示。
- 选单界面显示当前数据源；交互模式可随时切换文件/通道。

### Fixed

- `XmlGetEventId` 此前只匹配字面量 `<EventID>`，导致带 `Qualifiers` 属性的
  事件（导出的 `.evtx` 中很常见）被整条跳过。
- 爆破聚合命中结果现在可以随 `--export` 一起导出。

## [2.0.0] - 2026-10-28

- 首次公开：修复 CMake 与单元测试、P1 优化、CSV 公式注入防护、MIT LICENSE。
