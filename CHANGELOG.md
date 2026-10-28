# Changelog

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
