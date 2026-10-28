#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "xml_parser.h"

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
            printf("[FAIL] %s (line %d)\n", (msg), __LINE__); \
        } else { \
            printf("[PASS] %s\n", (msg)); \
        } \
    } while (0)

/* 校验整个字符串是合法 UTF-8（拒绝被截断的多字节序列） */
static int Utf8IsValid(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        int n;
        if (*p < 0x80) n = 0;
        else if ((*p & 0xE0) == 0xC0) n = 1;
        else if ((*p & 0xF0) == 0xE0) n = 2;
        else if ((*p & 0xF8) == 0xF0) n = 3;
        else return 0;
        p++;
        while (n-- > 0) {
            if ((*p & 0xC0) != 0x80) return 0;
            p++;
        }
    }
    return 1;
}

static const wchar_t *kXml4625 =
    L"<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">"
    L"<System><Provider Name=\"Microsoft-Windows-Security-Auditing\"/>"
    L"<EventID Qualifiers=\"16384\">4625</EventID>"
    L"<TimeCreated SystemTime=\"2026-10-28T02:00:00.1234567Z\"/>"
    L"</System><EventData>"
    L"<Data Name=\"TargetUserName\">DOMAIN\\admin</Data>"
    L"<Data Name=\"IpAddress\">203.0.113.7</Data>"
    L"<Data Name=\"LogonType\">3</Data>"
    L"<Data Name=\"ProcessName\">svchost.exe</Data>"
    L"</EventData></Event>";

static void TestEventId(void)
{
    int id = 0;

    CHECK(XmlGetEventId(kXml4625, &id) == 0, "EventID 带 Qualifiers 属性可解析");
    CHECK(id == 4625, "Qualifiers 属性事件 ID = 4625");

    CHECK(XmlGetEventId(L"<EventID>4624</EventID>", &id) == 0, "普通 EventID 可解析");
    CHECK(id == 4624, "普通 EventID = 4624");

    CHECK(XmlGetEventId(L"<EventIDX>1</EventIDX>", &id) == -1,
          "EventIDX 不会被误认为 EventID");

    CHECK(XmlGetEventId(L"<Event><System/></Event>", &id) == -1,
          "缺少 EventID 返回 -1");
}

static void TestDataValue(void)
{
    char buf[64];

    CHECK(XmlGetDataValue(kXml4625, L"TargetUserName", buf, sizeof(buf)) == 0,
          "双引号 Data 可读取");
    CHECK(strcmp(buf, "DOMAIN\\admin") == 0, "双引号 Data 值正确");

    CHECK(XmlGetDataValue(L"<Data Name='TargetUserName'>guest</Data>",
                          L"TargetUserName", buf, sizeof(buf)) == 0,
          "单引号 Data 可读取");
    CHECK(strcmp(buf, "guest") == 0, "单引号 Data 值正确");

    CHECK(XmlGetDataValue(kXml4625, L"NotExist", buf, sizeof(buf)) == -1,
          "不存在的 Data 返回 -1");
}

static void TestTimeCreated(void)
{
    char time[64];
    int len;

    CHECK(XmlGetTimeCreated(kXml4625, time, sizeof(time)) == 0,
          "TimeCreated 可解析");
    len = (int)strlen(time);
    CHECK(len == 19, "时间格式长度 19");
    CHECK(time[4] == '/' && time[7] == '/' && time[10] == '-' &&
          time[13] == ':' && time[16] == ':', "时间分隔符正确");
    CHECK(strncmp(time, "2026/", 5) == 0, "时间年份正确");

    CHECK(XmlGetTimeCreated(L"<TimeCreated SystemTime=\"bad\"/>", time, sizeof(time)) == -1,
          "非法时间返回 -1");
}

static void TestParseEvent(void)
{
    LogEntry e;

    CHECK(ParseEventXml(kXml4625, &e) == 0, "4625 XML 解析成功");
    CHECK(e.eventId == 4625, "解析出的 EventID 正确");
    CHECK(strcmp(e.userName, "DOMAIN\\admin") == 0, "解析出的用户名正确");
    CHECK(strcmp(e.sourceIP, "203.0.113.7") == 0, "解析出的源 IP 正确");
    CHECK(e.logOnType == 3, "解析出的 LogonType 正确");
    CHECK(strstr(e.processName, "svchost.exe") != NULL, "解析出的进程名正确");
    CHECK(strstr(e.description, "登录失败") != NULL, "4625 描述正确");

    CHECK(ParseEventXml(L"<Event><System/></Event>", &e) == -1,
          "缺少 EventID 的 XML 解析失败");
}

static void TestLongUserNameDescription(void)
{
    wchar_t user[400] = L"AB";
    wchar_t xml[2048];
    LogEntry e;
    int i;

    /* 2 字节 ASCII + 78 个汉字 = 236 字节，触发描述截断 */
    for (i = 0; i < 78; i++) wcscat(user, L"汉");

    swprintf(xml, 2048,
             L"<Event><System><EventID>4720</EventID>"
             L"<TimeCreated SystemTime=\"2026-10-28T02:00:00Z\"/>"
             L"</System><EventData>"
             L"<Data Name=\"TargetUserName\">%ls</Data>"
             L"</EventData></Event>", user);

    CHECK(ParseEventXml(xml, &e) == 0, "长用户名 4720 XML 解析成功");
    CHECK(strlen(e.description) < LOG_DESC_LEN, "描述长度未越界");
    CHECK(Utf8IsValid(e.description) == 1, "描述截断后仍是合法 UTF-8");
}

int main(void)
{
    TestEventId();
    TestDataValue();
    TestTimeCreated();
    TestParseEvent();
    TestLongUserNameDescription();

    printf("\n%d checks, %d failed.\n", g_total, g_failed);
    if (g_failed == 0) {
        printf("All XML tests passed!\n");
        return 0;
    }
    return 1;
}
