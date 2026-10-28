#include <stdio.h>
#include <string.h>

#include "filter.h"
#include "log_entry.h"

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

/* 构造一条模拟日志；未用到的字段保持空串/0 */
static LogEntry MakeLog(int eventId, const char *user,
                        const char *time, const char *ip)
{
    LogEntry log;
    memset(&log, 0, sizeof(log));
    log.eventId = eventId;
    CopyStr(log.userName, sizeof(log.userName), user);
    CopyStr(log.dateAndTime, sizeof(log.dateAndTime), time);
    CopyStr(log.sourceIP, sizeof(log.sourceIP), ip);
    return log;
}

int main(void)
{
    LogEntry log;

    /* ---------------- Filter_All ---------------- */
    log = MakeLog(4624, "user", "2026/10/28-10:00:00", "10.0.0.1");
    CHECK_EQ(1, Filter_All(&log), "Filter_All: 普通成功登录");
    memset(&log, 0, sizeof(log));
    CHECK_EQ(1, Filter_All(&log), "Filter_All: 全空记录也返回 1");

    /* ---------------- Filter_FailedLogin ---------------- */
    log = MakeLog(4625, "user", "2026/10/28-10:00:00", "10.0.0.1");
    CHECK_EQ(1, Filter_FailedLogin(&log), "Filter_FailedLogin: 4625 命中");
    log.eventId = 4624;
    CHECK_EQ(0, Filter_FailedLogin(&log), "Filter_FailedLogin: 4624 不命中");
    log.eventId = 4672;
    CHECK_EQ(0, Filter_FailedLogin(&log), "Filter_FailedLogin: 4672 不命中");

    /* ---------------- Filter_AdminFailed：精确、大小写、域名前缀 ---------------- */
    log = MakeLog(4625, "admin", "2026/10/28-10:00:00", "10.0.0.1");
    CHECK_EQ(1, Filter_AdminFailed(&log), "Filter_AdminFailed: admin 精确命中");

    log.userName[0] = '\0';
    CopyStr(log.userName, sizeof(log.userName), "ADMIN");
    CHECK_EQ(1, Filter_AdminFailed(&log), "Filter_AdminFailed: 大写 ADMIN 命中");

    CopyStr(log.userName, sizeof(log.userName), "DoMaIn\\admin");
    CHECK_EQ(1, Filter_AdminFailed(&log), "Filter_AdminFailed: DOMAIN\\admin 命中");

    CopyStr(log.userName, sizeof(log.userName), "WORKGROUP\\ADMIN");
    CHECK_EQ(1, Filter_AdminFailed(&log), "Filter_AdminFailed: 域名大小写混合也命中");

    CopyStr(log.userName, sizeof(log.userName), "administrator");
    CHECK_EQ(0, Filter_AdminFailed(&log), "Filter_AdminFailed: administrator 不误判为 admin");

    CopyStr(log.userName, sizeof(log.userName), "admin2");
    CHECK_EQ(0, Filter_AdminFailed(&log), "Filter_AdminFailed: admin2 不命中");

    CopyStr(log.userName, sizeof(log.userName), "");
    CHECK_EQ(0, Filter_AdminFailed(&log), "Filter_AdminFailed: 空用户名不命中");

    log = MakeLog(4624, "admin", "2026/10/28-10:00:00", "10.0.0.1");
    CHECK_EQ(0, Filter_AdminFailed(&log), "Filter_AdminFailed: 成功登录不命中");

    /* ---------------- Filter_BruteForce ---------------- */
    log = MakeLog(4625, "user", "2026/10/28-10:00:00", "10.0.0.1");
    CHECK_EQ(1, Filter_BruteForce(&log), "Filter_BruteForce: 4625 命中");
    log.eventId = 4624;
    CHECK_EQ(0, Filter_BruteForce(&log), "Filter_BruteForce: 4624 不命中");

    /* ---------------- Filter_NightLogin ---------------- */
    log = MakeLog(4624, "user", "2026/10/28-00:00:00", "10.0.0.1");
    CHECK_EQ(1, Filter_NightLogin(&log), "Filter_NightLogin: 00:00:00 命中");

    CopyStr(log.dateAndTime, sizeof(log.dateAndTime), "2026/10/28-03:15:00");
    CHECK_EQ(1, Filter_NightLogin(&log), "Filter_NightLogin: 03:15:00 命中");

    CopyStr(log.dateAndTime, sizeof(log.dateAndTime), "2026/10/28-05:59:59");
    CHECK_EQ(1, Filter_NightLogin(&log), "Filter_NightLogin: 05:59:59 边界命中");

    CopyStr(log.dateAndTime, sizeof(log.dateAndTime), "2026/10/28-06:00:00");
    CHECK_EQ(0, Filter_NightLogin(&log), "Filter_NightLogin: 06:00:00 边界不命中");

    CopyStr(log.dateAndTime, sizeof(log.dateAndTime), "2026/10/28-23:59:59");
    CHECK_EQ(0, Filter_NightLogin(&log), "Filter_NightLogin: 23:59:59 不命中");

    CopyStr(log.dateAndTime, sizeof(log.dateAndTime), "");
    CHECK_EQ(0, Filter_NightLogin(&log), "Filter_NightLogin: 空时间不误报为 0 点");

    CopyStr(log.dateAndTime, sizeof(log.dateAndTime), "2026/10/28");
    CHECK_EQ(0, Filter_NightLogin(&log), "Filter_NightLogin: 缺小时字段不误报");

    CopyStr(log.dateAndTime, sizeof(log.dateAndTime), "2026/10/28-xx:00:00");
    CHECK_EQ(0, Filter_NightLogin(&log), "Filter_NightLogin: 非数字小时不误报");

    CopyStr(log.dateAndTime, sizeof(log.dateAndTime), "2026/10/28-0a:00:00");
    CHECK_EQ(0, Filter_NightLogin(&log), "Filter_NightLogin: 半数字小时不误报");

    CopyStr(log.dateAndTime, sizeof(log.dateAndTime), "2026/10/28/03:15:00");
    CHECK_EQ(0, Filter_NightLogin(&log), "Filter_NightLogin: 分隔符错误不误报");

    log = MakeLog(4625, "user", "2026/10/28-03:15:00", "10.0.0.1");
    CHECK_EQ(0, Filter_NightLogin(&log), "Filter_NightLogin: 失败登录不算凌晨登录");

    /* ---------------- Filter_Privilege ---------------- */
    log = MakeLog(4672, "SYSTEM", "2026/10/28-10:00:00", "-");
    CHECK_EQ(1, Filter_Privilege(&log), "Filter_Privilege: 4672 命中");
    log.eventId = 4624;
    CHECK_EQ(0, Filter_Privilege(&log), "Filter_Privilege: 4624 不命中");

    /* ---------------- Filter_AccountCreated ---------------- */
    log = MakeLog(4720, "backdoor", "2026/10/28-10:00:00", "-");
    CHECK_EQ(1, Filter_AccountCreated(&log), "Filter_AccountCreated: 4720 命中");
    log.eventId = 4625;
    CHECK_EQ(0, Filter_AccountCreated(&log), "Filter_AccountCreated: 4625 不命中");

    /* ---------------- Filter_HasSourceIp：聚合前的 "-" IP 边界 ---------------- */
    CHECK_EQ(0, Filter_HasSourceIp(""), "Filter_HasSourceIp: 空串不可聚合");
    CHECK_EQ(0, Filter_HasSourceIp("-"), "Filter_HasSourceIp: \"-\" 不可聚合");
    CHECK_EQ(1, Filter_HasSourceIp("192.168.1.5"), "Filter_HasSourceIp: IPv4 可聚合");
    CHECK_EQ(1, Filter_HasSourceIp("::1"), "Filter_HasSourceIp: IPv6 可聚合");

    printf("\n%d checks, %d failed.\n", g_total, g_failed);
    if (g_failed == 0) {
        printf("All filter tests passed!\n");
        return 0;
    }
    return 1;
}
