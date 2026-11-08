#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#include "daterange.h"
#include "console_utf8.h"

static int g_total = 0;
static int g_failed = 0;

#define CHECK(cond, msg) \
    do { \
        g_total++; \
        if (!(cond)) { \
            g_failed++; \
            printf("[FAIL] %s (line %d)\n", (msg), __LINE__); \
        } else { \
            printf("[PASS] %s\n", (msg)); \
        } \
    } while (0)

#define CHECK_WSTR(expected, actual, msg) \
    do { \
        g_total++; \
        if (wcscmp((expected), (actual)) != 0) { \
            g_failed++; \
            printf("[FAIL] %s (expected \"%ls\", actual \"%ls\")\n", \
                   (msg), (expected), (actual)); \
        } else { \
            printf("[PASS] %s\n", (msg)); \
        } \
    } while (0)

/* 本地时间 -> FILETIME -> 本地时间，字段应当原样回来（和 XmlGetTimeCreated 同一套逆变换） */
static int RoundTrip(const wchar_t *text, SYSTEMTIME *back)
{
    FILETIME ft;
    SYSTEMTIME utc;

    if (DateRange_ParseLocal(text, &ft) != 0) return 0;
    if (!FileTimeToSystemTime(&ft, &utc)) return 0;
    if (!SystemTimeToTzSpecificLocalTime(NULL, &utc, back)) return 0;
    return 1;
}

static void TestParseValid(void)
{
    SYSTEMTIME t;

    CHECK(RoundTrip(L"2026-06-15", &t) && t.wYear == 2026 && t.wMonth == 6 &&
          t.wDay == 15 && t.wHour == 0 && t.wMinute == 0 && t.wSecond == 0,
          "解析日期，时间默认为 00:00:00");

    CHECK(RoundTrip(L"2026-06-15 08:30:15", &t) && t.wHour == 8 &&
          t.wMinute == 30 && t.wSecond == 15,
          "解析日期 + 时分秒");

    CHECK(RoundTrip(L"2026-06-15 08:30", &t) && t.wHour == 8 && t.wMinute == 30 &&
          t.wSecond == 0, "解析日期 + 时分（秒默认 0）");

    CHECK(RoundTrip(L"2026-06-15T08:30:15", &t) && t.wHour == 8,
          "允许用 T 分隔日期和时间");

    CHECK(RoundTrip(L"2024-02-29", &t) && t.wDay == 29, "闰年 2 月 29 日合法");
}

static void TestParseInvalid(void)
{
    FILETIME ft;

    CHECK(DateRange_ParseLocal(L"2025-02-29", &ft) == -1, "平年 2 月 29 日被拒绝");
    CHECK(DateRange_ParseLocal(L"2026-13-01", &ft) == -1, "13 月被拒绝");
    CHECK(DateRange_ParseLocal(L"2026-00-10", &ft) == -1, "0 月被拒绝");
    CHECK(DateRange_ParseLocal(L"2026-04-31", &ft) == -1, "4 月 31 日被拒绝");
    CHECK(DateRange_ParseLocal(L"2026-06-15 24:00:00", &ft) == -1, "24 点被拒绝");
    CHECK(DateRange_ParseLocal(L"2026-06-15 08:60:00", &ft) == -1, "60 分被拒绝");
    CHECK(DateRange_ParseLocal(L"2026-06-15 08:30:60", &ft) == -1, "60 秒被拒绝");
    CHECK(DateRange_ParseLocal(L"2026/06/15", &ft) == -1, "斜杠分隔被拒绝");
    CHECK(DateRange_ParseLocal(L"26-06-15", &ft) == -1, "两位年份被拒绝");
    CHECK(DateRange_ParseLocal(L"", &ft) == -1, "空串被拒绝");
    CHECK(DateRange_ParseLocal(L"2026-06-15 08", &ft) == -1, "只有小时被拒绝");
    CHECK(DateRange_ParseLocal(L"2026-06-15 08:30:15x", &ft) == -1, "尾部多余字符被拒绝");
}

static void TestIso8601(void)
{
    SYSTEMTIME utc;
    FILETIME ft;
    wchar_t iso[32];

    memset(&utc, 0, sizeof(utc));
    utc.wYear = 2026;
    utc.wMonth = 6;
    utc.wDay = 15;
    utc.wHour = 0;
    utc.wMinute = 0;
    utc.wSecond = 0;
    CHECK(SystemTimeToFileTime(&utc, &ft) != 0, "构造 UTC FILETIME");

    DateRange_ToIso8601(&ft, iso, sizeof(iso) / sizeof(iso[0]));
    CHECK_WSTR(L"2026-06-15T00:00:00.000Z", iso, "FILETIME 转 ISO 8601");
    CHECK(wcslen(iso) == 24, "ISO 8601 长度固定 24");
}

static void TestBuildXpath(void)
{
    FILETIME since;
    FILETIME until;
    wchar_t buf[512];
    wchar_t small[8];
    SYSTEMTIME utc;

    memset(&utc, 0, sizeof(utc));
    utc.wYear = 2026;
    utc.wMonth = 6;
    utc.wDay = 15;
    CHECK(SystemTimeToFileTime(&utc, &since) != 0, "构造 since");
    utc.wDay = 16;
    CHECK(SystemTimeToFileTime(&utc, &until) != 0, "构造 until");

    CHECK(DateRange_BuildXpath(L"EventID=4624", NULL, NULL, buf, 512) == 0, "只有 EventID");
    CHECK_WSTR(L"*[System[(EventID=4624)]]", buf, "EventID 组带括号");

    CHECK(DateRange_BuildXpath(L"", &since, NULL, buf, 512) == 0, "只有 since");
    CHECK_WSTR(L"*[System[TimeCreated[@SystemTime>='2026-06-15T00:00:00.000Z']]]", buf,
               "空 EventID 时不出现空括号");

    CHECK(DateRange_BuildXpath(L"", &since, &until, buf, 512) == 0, "since + until");
    CHECK_WSTR(L"*[System[TimeCreated[@SystemTime>='2026-06-15T00:00:00.000Z'] "
               L"and TimeCreated[@SystemTime<='2026-06-16T00:00:00.000Z']]]", buf,
               "两个时间条件用 and 连接");

    CHECK(DateRange_BuildXpath(L"EventID=4624 or EventID=4625", &since, &until, buf, 512) == 0,
          "EventID + 两个时间");
    CHECK_WSTR(L"*[System[(EventID=4624 or EventID=4625) "
               L"and TimeCreated[@SystemTime>='2026-06-15T00:00:00.000Z'] "
               L"and TimeCreated[@SystemTime<='2026-06-16T00:00:00.000Z']]]", buf,
               "三段条件顺序稳定");

    CHECK(DateRange_BuildXpath(L"", NULL, NULL, buf, 512) == 0, "无条件时不报错");
    CHECK_WSTR(L"*", buf, "无条件时退化成 *");

    CHECK(DateRange_BuildXpath(L"EventID=4624", &since, NULL, small, 8) == -1,
          "缓冲区不够时返回 -1");
}

int main(void)
{
    TestConsoleUtf8();
    TestParseValid();
    TestParseInvalid();
    TestIso8601();
    TestBuildXpath();

    printf("\n%d checks, %d failed.\n", g_total, g_failed);
    if (g_failed == 0) {
        printf("All daterange tests passed!\n");
        return 0;
    }
    return 1;
}
