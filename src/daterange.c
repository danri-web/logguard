#include <stdio.h>
#include <wchar.h>

#include "daterange.h"

/* FILETIME 的起点是 1601-01-01，早于它的年份没有意义 */
#define DATERANGE_MIN_YEAR 1601

static int IsLeapYear(int y)
{
    return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
}

static int DaysInMonth(int y, int m)
{
    static const int days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (m < 1 || m > 12) return 0;
    if (m == 2 && IsLeapYear(y)) return 29;
    return days[m - 1];
}

/* 从 *p 读 n 位数字，成功后把指针前移；失败返回 0 */
static int ReadDigits(const wchar_t **p, int n, int *out)
{
    int value = 0;
    int i;

    for (i = 0; i < n; i++) {
        wchar_t c = (*p)[i];
        if (c < L'0' || c > L'9') return 0;
        value = value * 10 + (int)(c - L'0');
    }
    *p += n;
    *out = value;
    return 1;
}

int DateRange_ParseLocal(const wchar_t *text, FILETIME *out)
{
    const wchar_t *p;
    int year, month, day;
    int hour = 0, minute = 0, second = 0;
    SYSTEMTIME localTime;
    SYSTEMTIME utcTime;

    if (text == NULL || out == NULL) return -1;

    p = text;
    while (*p == L' ' || *p == L'\t') p++;

    if (!ReadDigits(&p, 4, &year)) return -1;
    if (*p != L'-') return -1;
    p++;
    if (!ReadDigits(&p, 2, &month)) return -1;
    if (*p != L'-') return -1;
    p++;
    if (!ReadDigits(&p, 2, &day)) return -1;

    /* "YYYY-MM-DD" 之后可以没有时间；有就必需是 HH:MM[:SS] */
    if (*p != L'\0') {
        if (*p != L' ' && *p != L'T') return -1;
        p++;
        if (!ReadDigits(&p, 2, &hour)) return -1;
        if (*p != L':') return -1;
        p++;
        if (!ReadDigits(&p, 2, &minute)) return -1;
        if (*p == L':') {
            p++;
            if (!ReadDigits(&p, 2, &second)) return -1;
        }
        while (*p == L' ' || *p == L'\t') p++;
        if (*p != L'\0') return -1;
    }

    if (year < DATERANGE_MIN_YEAR) return -1;
    if (month < 1 || month > 12) return -1;
    if (day < 1 || day > DaysInMonth(year, month)) return -1;
    if (hour > 23 || minute > 59 || second > 59) return -1;

    localTime.wYear         = (WORD)year;
    localTime.wMonth        = (WORD)month;
    localTime.wDay          = (WORD)day;
    localTime.wHour         = (WORD)hour;
    localTime.wMinute       = (WORD)minute;
    localTime.wSecond       = (WORD)second;
    localTime.wMilliseconds = 0;
    localTime.wDayOfWeek    = 0;

    /*
     * 本地 -> UTC：用系统当前时区规则（和 XmlGetTimeCreated 的显示口径一致）。
     * 夏令时切换的「不存在的那一小时」会失败，这是正确行为，不该悄悄猜一个值。
     */
    if (!TzSpecificLocalTimeToSystemTime(NULL, &localTime, &utcTime)) return -1;

    utcTime.wMilliseconds = 0;
    if (!SystemTimeToFileTime(&utcTime, out)) return -1;
    return 0;
}

void DateRange_ToIso8601(const FILETIME *ft, wchar_t *buf, size_t len)
{
    SYSTEMTIME st;

    if (buf == NULL || len == 0) return;
    buf[0] = L'\0';
    if (ft == NULL) return;
    if (!FileTimeToSystemTime(ft, &st)) return;

    swprintf(buf, len, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
             (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
             (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
             (unsigned)st.wMilliseconds);
}

/* 往 cond 末尾追加一个条件；条件之间用 " and " 连接 */
static int AppendCondition(wchar_t *cond, size_t len, const wchar_t *piece,
                           int withAnd)
{
    int written;

    if (withAnd) {
        written = swprintf(cond + wcslen(cond), len - wcslen(cond), L" and %ls", piece);
    } else {
        written = swprintf(cond + wcslen(cond), len - wcslen(cond), L"%ls", piece);
    }
    return written >= 0 ? 0 : -1;
}

int DateRange_BuildXpath(const wchar_t *pred,
                         const FILETIME *since, const FILETIME *until,
                         wchar_t *out, size_t len)
{
    wchar_t cond[384];
    wchar_t isoSince[32];
    wchar_t isoUntil[32];
    wchar_t piece[160];
    int hasCond = 0;

    if (out == NULL || len == 0) return -1;

    cond[0] = L'\0';

    if (pred != NULL && pred[0] != L'\0') {
        /* EventID 组本身是 or 连接，必须加括号，否则会和后面的 and 抢结合性 */
        swprintf(piece, sizeof(piece) / sizeof(piece[0]), L"(%ls)", pred);
        if (AppendCondition(cond, sizeof(cond) / sizeof(cond[0]), piece, 0) != 0) return -1;
        hasCond = 1;
    }

    if (since != NULL) {
        DateRange_ToIso8601(since, isoSince, sizeof(isoSince) / sizeof(isoSince[0]));
        if (isoSince[0] == L'\0') return -1;
        swprintf(piece, sizeof(piece) / sizeof(piece[0]),
                 L"TimeCreated[@SystemTime>='%ls']", isoSince);
        if (AppendCondition(cond, sizeof(cond) / sizeof(cond[0]), piece, hasCond) != 0) return -1;
        hasCond = 1;
    }

    if (until != NULL) {
        DateRange_ToIso8601(until, isoUntil, sizeof(isoUntil) / sizeof(isoUntil[0]));
        if (isoUntil[0] == L'\0') return -1;
        swprintf(piece, sizeof(piece) / sizeof(piece[0]),
                 L"TimeCreated[@SystemTime<='%ls']", isoUntil);
        if (AppendCondition(cond, sizeof(cond) / sizeof(cond[0]), piece, hasCond) != 0) return -1;
        hasCond = 1;
    }

    /* 一个条件都没有时，调用方应该直接用 "*"；这里仍然给一个合法结果 */
    if (!hasCond) {
        if (swprintf(out, len, L"*") < 0) return -1;
        return 0;
    }

    if (swprintf(out, len, L"*[System[%ls]]", cond) < 0) return -1;
    return 0;
}
