# Changelog

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
