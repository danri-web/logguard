#ifndef LOG_READER_H
#define LOG_READER_H

#include <stddef.h>
#include <windows.h>
#include "log_entry.h"

/*
 * 从「本机通道」或「.evtx 文件」读取事件，解析后写入 out。
 * 参数：
 *   target   通道名（如 L"Security"）或 .evtx 文件路径
 *   isFile   0 = target 是本机通道；1 = target 是 .evtx 文件
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
 * 注意：读取本机 Security 通道需要管理员权限；读取 .evtx 文件不需要。
 */
int ReadLogs(const wchar_t *target, int isFile,
             LogEntry *out, int maxCount,
             const wchar_t *xpath,
             wchar_t *errBuf, size_t errLen);

/*
 * 读取本机 Security 通道（ReadLogs 的便捷封装，保留给旧调用方）。
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