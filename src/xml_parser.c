#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#include "xml_parser.h"

/* 内部辅助：宽字符转 UTF-8，并保证截断安全 */
static void WideToUtf8(const wchar_t *src, size_t srcLen, char *dst, size_t dstLen)
{
    if (dstLen == 0) return;
    int converted = WideCharToMultiByte(CP_UTF8, 0, src, (int)srcLen, dst, (int)dstLen - 1, NULL, NULL);
    if (converted >= 0) {
        dst[converted] = '\0';
    } else {
        dst[0] = '\0';
    }
}

/*
 * 把 prefix + userName + suffix 拼进 dst。
 * userName 过长时按 UTF-8 字符边界截断（不会切出半个汉字），
 * 避免 snprintf("%s") 直接截断导致乱码。
 */
static void FormatUserDescription(char *dst, size_t dstLen, const char *prefix,
                                  const char *userName, const char *suffix)
{
    size_t prefixLen = strlen(prefix);
    size_t suffixLen = strlen(suffix);
    size_t userLen;
    size_t room;

    if (dstLen == 0) return;
    if (prefixLen + suffixLen + 1 >= dstLen) {
        dst[0] = '\0';
        return;
    }

    memcpy(dst, prefix, prefixLen);
    room = dstLen - 1 - prefixLen - suffixLen;

    userLen = strlen(userName);
    if (userLen > room) {
        userLen = room;
        /* 回退到 UTF-8 字符起点 */
        while (userLen > 0 && ((unsigned char)userName[userLen] & 0xC0) == 0x80) {
            userLen--;
        }
    }

    memcpy(dst + prefixLen, userName, userLen);
    memcpy(dst + prefixLen + userLen, suffix, suffixLen);
    dst[prefixLen + userLen + suffixLen] = '\0';
}

int XmlGetEventId(const wchar_t *xml, int *eventId)
{
    const wchar_t *start = wcsstr(xml, L"<EventID>");
    if (!start) return -1;
    start += 9; // 跳过 "<EventID>"
    
    return swscanf(start, L"%d", eventId) == 1 ? 0 : -1;
}

int XmlGetDataValue(const wchar_t *xml, const wchar_t *name, char *out, size_t outLen)
{
    if (outLen == 0) return -1;
    out[0] = '\0';

    wchar_t prefix[128];
    const wchar_t *start = NULL;

    // 尝试双引号: <Data Name="xxx">
    swprintf(prefix, 128, L"<Data Name=\"%ls\">", name);
    start = wcsstr(xml, prefix);
    if (start) {
        start += wcslen(prefix);
    } else {
        // 尝试单引号: <Data Name='xxx'>
        swprintf(prefix, 128, L"<Data Name='%ls'>", name);
        start = wcsstr(xml, prefix);
        if (start) {
            start += wcslen(prefix);
        }
    }

    if (!start) return -1;
    
    const wchar_t *end = wcsstr(start, L"</Data>");
    if (!end) return -1;

    size_t len = end - start;
    WideToUtf8(start, len, out, outLen);
    return 0;
}

int XmlGetTimeCreated(const wchar_t *xml, char *out, size_t outLen)
{
    if (outLen == 0) return -1;
    out[0] = '\0';

    const wchar_t *start = NULL;
    const wchar_t *prefix1 = L"<TimeCreated SystemTime=\"";
    const wchar_t *prefix2 = L"<TimeCreated SystemTime='";

    start = wcsstr(xml, prefix1);
    if (start) start += wcslen(prefix1);
    else {
        start = wcsstr(xml, prefix2);
        if (start) start += wcslen(prefix2);
    }

    if (!start) return -1;
    
    wchar_t timeStr[64] = {0};
    int i = 0;
    while (start[i] != L'"' && start[i] != L'\'' && start[i] != L'\0' && i < 63) {
        timeStr[i] = start[i];
        i++;
    }
    timeStr[i] = L'\0';

    int year, month, day, hour, min, sec;
    if (swscanf(timeStr, L"%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &min, &sec) == 6) {
        SYSTEMTIME utc = {0};
        SYSTEMTIME local = {0};

        utc.wYear         = (WORD)year;
        utc.wMonth        = (WORD)month;
        utc.wDay          = (WORD)day;
        utc.wHour         = (WORD)hour;
        utc.wMinute       = (WORD)min;
        utc.wSecond       = (WORD)sec;
        utc.wMilliseconds = 0;

        /* 按系统当前时区/夏令时规则转换，不再硬编码 UTC+8 */
        if (!SystemTimeToTzSpecificLocalTime(NULL, &utc, &local)) {
            return -1;
        }

        snprintf(out, outLen, "%04d/%02d/%02d-%02d:%02d:%02d",
                 local.wYear, local.wMonth, local.wDay,
                 local.wHour, local.wMinute, local.wSecond);
        return 0;
    }
    return -1;
}

int ParseEventXml(const wchar_t *xml, LogEntry *out)
{
    if (!xml || !out) return -1;
    memset(out, 0, sizeof(LogEntry));

    if (XmlGetEventId(xml, &out->eventId) != 0) return -1;
    
    XmlGetTimeCreated(xml, out->dateAndTime, LOG_TIME_LEN);
    XmlGetDataValue(xml, L"IpAddress", out->sourceIP, LOG_IP_LEN);
    XmlGetDataValue(xml, L"ProcessName", out->processName, LOG_PROC_LEN);

    if (XmlGetDataValue(xml, L"TargetUserName", out->userName, LOG_USER_LEN) != 0) {
        XmlGetDataValue(xml, L"SubjectUserName", out->userName, LOG_USER_LEN);
    }

    char typeStr[16] = {0};
    if (XmlGetDataValue(xml, L"LogonType", typeStr, sizeof(typeStr)) == 0) {
        out->logOnType = atoi(typeStr);
    }

        // 找到 ParseEventXml 里面的这段代码并替换：
    if (out->eventId == 4624) {
        snprintf(out->description, LOG_DESC_LEN, "登录成功：LogonType %d", out->logOnType);
    } else if (out->eventId == 4625) {
        snprintf(out->description, LOG_DESC_LEN, "登录失败：用户名或密码错误");
    } else if (out->eventId == 4672) {
        snprintf(out->description, LOG_DESC_LEN, "安全告警：分配了特殊特权 (疑似提权)");
    } else if (out->eventId == 4720) {
        // 对于 4720 事件，TargetUserName 就是被创建的新账号
        FormatUserDescription(out->description, LOG_DESC_LEN,
                              "安全告警：创建了新系统账户 [", out->userName, "]");
    } else {
        snprintf(out->description, LOG_DESC_LEN, "其他事件");
    }

    return 0;
}