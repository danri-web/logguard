#ifndef LOG_READER_H
#define LOG_READER_H

#include <stddef.h>
#include <windows.h>
#include "log_entry.h"

/*
 * 读取本机 Security 通道中匹配 xpath 的登录事件，解析后写入 out。
 * 参数：
 *   out      调用方提供的数组，长度 >= maxCount
 *   maxCount 数组容量
 *   xpath    宽字符 XPath 过滤条件，例如
 *            L"*[System[(EventID=4624 or EventID=4625)]]"
 *   errBuf   失败时写入错误描述（宽字符），可为 NULL
 *   errLen   errBuf 的字符数
 * 返回：
 *   >=0 实际读取并解析成功的条数（可能小于 maxCount）
 *   <0  失败，具体错误在 errBuf 中（若提供）
 *
 * 注意：调用此函数需要管理员权限，否则 EvtQuery 会返回 ERROR_ACCESS_DENIED。
 */
int ReadSecurityLogs(LogEntry *out, int maxCount,
                     const wchar_t *xpath,
                     wchar_t *errBuf, size_t errLen);

/*
 * 把 Win32 错误码格式化为可读的宽字符串（用于 errBuf）。
 * 内部调用 FormatMessageW。
 */
void FormatWinError(DWORD code, wchar_t *buf, size_t len);

#endif /* LOG_READER_H */