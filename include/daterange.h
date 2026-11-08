#ifndef DATERANGE_H
#define DATERANGE_H

#include <stddef.h>
#include <windows.h>

/*
 * 时间范围（--since / --until）。
 *
 * 所有输入都按「本地时间」解释，和屏幕上显示的 "YYYY/MM/DD-HH:MM:SS" 同一口径；
 * 转成 UTC FILETIME 后再拼进 XPath —— Windows 事件日志的 SystemTime 是 UTC，
 * 直接拿本地时间去比会差一个时区，夜里跨天时差 8 小时最明显。
 */

/*
 * 解析 "YYYY-MM-DD"、"YYYY-MM-DD HH:MM"、"YYYY-MM-DD HH:MM:SS"。
 * 分隔符允许空格或 'T'；日期必须真实存在（含闰年）。
 * 返回：0 成功，-1 格式错误 / 日期不存在 / 本地时间落进夏令时空档。
 */
int DateRange_ParseLocal(const wchar_t *text, FILETIME *out);

/*
 * FILETIME（UTC）格式化为 XPath 用的 ISO 8601："2026-11-08T00:00:00.000Z"。
 * buf 至少 32 个宽字符。
 */
void DateRange_ToIso8601(const FILETIME *ft, wchar_t *buf, size_t len);

/*
 * 拼查询条件：
 *   *[System[(<pred>) and TimeCreated[@SystemTime>='...'] and TimeCreated[@SystemTime<='...']]]
 * pred 为 EventID 那一组条件；空串表示不按 EventID 收窄。
 * since / until 可为 NULL（表示不限）。
 * 返回：0 成功，-1 参数非法或缓冲区不够。
 */
int DateRange_BuildXpath(const wchar_t *pred,
                         const FILETIME *since, const FILETIME *until,
                         wchar_t *out, size_t len);

#endif /* DATERANGE_H */
