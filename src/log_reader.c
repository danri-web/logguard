#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>
#include <winevt.h>

#include "log_reader.h"
#include "xml_parser.h"

void FormatWinError(DWORD code, wchar_t *buf, size_t len)
{
    if (!buf || len == 0) return;
    buf[0] = L'\0';
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   buf, (DWORD)len, NULL);
}

/* 去掉 FormatMessageW 附带的换行/空白，便于拼进一行提示 */
static void TrimTrailingSpace(wchar_t *s)
{
    size_t n = wcslen(s);
    while (n > 0 && (s[n - 1] == L'\r' || s[n - 1] == L'\n' ||
                     s[n - 1] == L' '  || s[n - 1] == L'\t')) {
        s[--n] = L'\0';
    }
}

/* 把「错误码 + 系统描述」写入 errBuf，例如 "错误码 5：拒绝访问。" */
static void FormatWinErrorWithCode(DWORD code, wchar_t *buf, size_t len)
{
    wchar_t desc[256] = {0};
    if (!buf || len == 0) return;

    FormatWinError(code, desc, sizeof(desc) / sizeof(desc[0]));
    TrimTrailingSpace(desc);

    if (desc[0] != L'\0') {
        swprintf(buf, len, L"错误码 %lu：%ls", (unsigned long)code, desc);
    } else {
        swprintf(buf, len, L"错误码 %lu", (unsigned long)code);
    }
}

int ReadLogs(const wchar_t *target, int isFile,
             LogEntry *out, int maxCount, const wchar_t *xpath,
             wchar_t *errBuf, size_t errLen)
{
    if (!target || !out || maxCount <= 0 || !xpath) return -1;

    // 1. 发起查询
    // EvtQueryChannelPath: 查询本机通道；EvtQueryFilePath: 查询 .evtx 文件
    // EvtQueryReverseDirection: 逆序（最新的日志在前）
    DWORD queryFlags = (isFile ? EvtQueryFilePath : EvtQueryChannelPath)
                     | EvtQueryReverseDirection;
    EVT_HANDLE hQuery = EvtQuery(NULL, target, xpath, queryFlags);
    if (!hQuery) {
        if (errBuf) FormatWinErrorWithCode(GetLastError(), errBuf, errLen);
        return -1;
    }

    int count = 0;
    DWORD dwReturned = 0;
    EVT_HANDLE events[16]; // 每次批量取 16 条

    // 2. 循环提取事件
    while (EvtNext(hQuery, 16, events, INFINITE, 0, &dwReturned)) {
        for (DWORD i = 0; i < dwReturned; i++) {
            DWORD dwBufferSize = 0;
            DWORD dwBufferUsed = 0;
            DWORD dwPropertyCount = 0;

            // 3. 第一次 Render 获取所需的 XML 缓冲区大小
            if (!EvtRender(NULL, events[i], EvtRenderEventXml, dwBufferSize, NULL, &dwBufferUsed, &dwPropertyCount)) {
                DWORD status = GetLastError();
                if (status == ERROR_INSUFFICIENT_BUFFER) {
                    dwBufferSize = dwBufferUsed;
                    // 分配内存 (Windows API 返回的 dwBufferSize 是字节数)
                    wchar_t *pXml = (wchar_t*)malloc(dwBufferSize);
                    if (pXml) {
                        // 4. 第二次 Render 获取实际数据
                        if (EvtRender(NULL, events[i], EvtRenderEventXml, dwBufferSize, pXml, &dwBufferUsed, &dwPropertyCount)) {
                            // 5. 解析 XML 进结构体
                            if (ParseEventXml(pXml, &out[count]) == 0) {
                                count++;
                                if (count >= maxCount) {
                                    free(pXml);
                                    EvtClose(events[i]);
                                    // 已达到要求条数，清理并退出
                                    for(DWORD j=i+1; j<dwReturned; j++) EvtClose(events[j]);
                                    goto cleanup;
                                }
                            }
                        }
                        free(pXml);
                    }
                }
            }
            EvtClose(events[i]);
        }
    }

cleanup:
    EvtClose(hQuery);
    return count;
}

int ReadSecurityLogs(LogEntry *out, int maxCount, const wchar_t *xpath,
                     wchar_t *errBuf, size_t errLen)
{
    return ReadLogs(L"Security", 0, out, maxCount, xpath, errBuf, errLen);
}