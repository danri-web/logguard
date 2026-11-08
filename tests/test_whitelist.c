#include <stdio.h>
#include <string.h>

#include "whitelist.h"
#include "log_entry.h"
#include "console_utf8.h"

static int g_total = 0;
static int g_failed = 0;

#define CHECK_EQ(expected, actual, msg) \
    do { \
        int exp_ = (expected); \
        int act_ = (actual); \
        g_total++; \
        if (exp_ != act_) { \
            g_failed++; \
            printf("[FAIL] %s (expected %d, actual %d, line %d)\n", \
                   (msg), exp_, act_, __LINE__); \
        } else { \
            printf("[PASS] %s\n", (msg)); \
        } \
    } while (0)

static void CopyStr(char *dst, size_t dstLen, const char *src)
{
    size_t n = strlen(src);
    if (n >= dstLen) n = dstLen - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static LogEntry MakeLog(const char *user, const char *ip)
{
    LogEntry log;
    memset(&log, 0, sizeof(log));
    CopyStr(log.userName, sizeof(log.userName), user);
    CopyStr(log.sourceIP, sizeof(log.sourceIP), ip);
    return log;
}

static void TestParseLine(void)
{
    Whitelist wl;

    Whitelist_Init(&wl);
    CHECK_EQ(0, Whitelist_ParseLine(&wl, ""), "空行被忽略");
    CHECK_EQ(0, Whitelist_ParseLine(&wl, "   "), "全是空格的行被忽略");
    CHECK_EQ(0, Whitelist_ParseLine(&wl, "# ip 1.2.3.4"), "井号注释被忽略");
    CHECK_EQ(0, Whitelist_ParseLine(&wl, "; user admin"), "分号注释被忽略");

    CHECK_EQ(1, Whitelist_ParseLine(&wl, "ip 10.0.0.5"), "ip 规则");
    CHECK_EQ(1, Whitelist_ParseLine(&wl, "  IP   10.0.0.6  "), "大小写和首尾空白都容忍");
    CHECK_EQ(1, Whitelist_ParseLine(&wl, "user CORP\\svc_backup"), "user 规则带域");
    CHECK_EQ(1, Whitelist_ParseLine(&wl, "user\tsvc_sql"), "tab 作为分隔符");
    CHECK_EQ(4, wl.count, "一共 4 条规则");

    CHECK_EQ(-1, Whitelist_ParseLine(&wl, "bogus 10.0.0.7"), "未知类型被拒绝");
    CHECK_EQ(-1, Whitelist_ParseLine(&wl, "ip"), "只有类型没有值被拒绝");
    CHECK_EQ(-1, Whitelist_ParseLine(&wl, "ip "), "值全是空白被拒绝");
    CHECK_EQ(4, wl.count, "被拒绝的行不进入规则表");
}

static void TestMatch(void)
{
    Whitelist wl;
    LogEntry log;

    Whitelist_Init(&wl);
    Whitelist_ParseLine(&wl, "ip 10.0.0.5");
    Whitelist_ParseLine(&wl, "user svc_backup");
    Whitelist_ParseLine(&wl, "user CORP\\svc_sql");

    log = MakeLog("alice", "10.0.0.5");
    CHECK_EQ(1, Whitelist_Match(&wl, &log), "IP 精确命中");

    log = MakeLog("alice", "10.0.0.50");
    CHECK_EQ(0, Whitelist_Match(&wl, &log), "IP 不做前缀匹配");

    log = MakeLog("CORP\\svc_backup", "10.0.0.1");
    CHECK_EQ(1, Whitelist_Match(&wl, &log), "账户名去域前缀后命中");

    log = MakeLog("SVC_BACKUP", "10.0.0.1");
    CHECK_EQ(1, Whitelist_Match(&wl, &log), "账户名大小写无关");

    log = MakeLog("CORP\\svc_sql", "10.0.0.1");
    CHECK_EQ(1, Whitelist_Match(&wl, &log), "带域的规则命中完整账户名");

    log = MakeLog("svc_sql", "10.0.0.1");
    CHECK_EQ(0, Whitelist_Match(&wl, &log), "带域规则不匹配去掉域的名字");

    /* "-" 是 Windows 的「无来源」占位值，规则不该把它吃掉 */
    log = MakeLog("bob", "-");
    CHECK_EQ(0, Whitelist_Match(&wl, &log), "\"-\" 不会被 IP 规则命中");
}

static void TestFilter(void)
{
    Whitelist wl;
    LogEntry logs[4];
    int dropped;

    Whitelist_Init(&wl);
    Whitelist_ParseLine(&wl, "ip 10.0.0.5");
    Whitelist_ParseLine(&wl, "user svc");

    logs[0] = MakeLog("alice", "10.0.0.5");   /* 剔除 */
    logs[1] = MakeLog("bob", "10.0.0.6");
    logs[2] = MakeLog("svc", "10.0.0.7");     /* 剔除 */
    logs[3] = MakeLog("carol", "10.0.0.8");

    dropped = Whitelist_Filter(logs, 4, &wl);
    CHECK_EQ(2, dropped, "剔除 2 条");
    CHECK_EQ(1, strcmp(logs[0].userName, "bob") == 0, "剩下第一条是 bob（原地压缩）");
    CHECK_EQ(1, strcmp(logs[1].userName, "carol") == 0, "剩下第二条是 carol");

    dropped = Whitelist_Filter(logs, 2, &wl);
    CHECK_EQ(0, dropped, "再跑一次没有可剔除的");
}

static void TestEmptyAndOverflow(void)
{
    Whitelist wl;
    LogEntry log;
    int i;
    int accepted = 0;

    Whitelist_Init(&wl);
    log = MakeLog("alice", "10.0.0.5");
    CHECK_EQ(0, Whitelist_Match(&wl, &log), "空白名单不命中任何记录");
    CHECK_EQ(0, Whitelist_Filter(&log, 1, &wl), "空白名单不动数组");

    for (i = 0; i < WHITELIST_MAX_RULES; i++) {
        char line[64];
        snprintf(line, sizeof(line), "ip 10.0.%d.%d", i / 256, i % 256);
        if (Whitelist_ParseLine(&wl, line) == 1) accepted++;
    }
    CHECK_EQ(WHITELIST_MAX_RULES, accepted, "规则表能装满");
    CHECK_EQ(-1, Whitelist_ParseLine(&wl, "ip 192.168.0.1"), "超出上限后拒绝新规则");
}

int main(void)
{
    TestConsoleUtf8();
    TestParseLine();
    TestMatch();
    TestFilter();
    TestEmptyAndOverflow();

    printf("\n%d checks, %d failed.\n", g_total, g_failed);
    if (g_failed == 0) {
        printf("All whitelist tests passed!\n");
        return 0;
    }
    return 1;
}
