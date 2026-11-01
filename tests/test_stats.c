#include <stdio.h>
#include <string.h>

#include "stats.h"
#include "log_entry.h"
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

#define CHECK_STR(expected, actual, msg) \
    do { \
        const char *exp_ = (expected); \
        const char *act_ = (actual); \
        g_total++; \
        if (strcmp(exp_, act_) != 0) { \
            g_failed++; \
            printf("[FAIL] %s (expected \"%s\", actual \"%s\", line %d)\n", \
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

static void TestParamErrors(void)
{
    LogEntry logs[1];
    StatsSummary s;

    logs[0] = MakeLog(4624, "user", "2026/10/28-10:00:00", "10.0.0.1");

    CHECK_EQ(0, Stats_Compute(NULL, 0, &s), "空输入：count=0 且 logs=NULL 返回成功");
    CHECK_EQ(0, s.total, "空输入：total 为 0");
    CHECK_EQ(0, s.eventKindCount, "空输入：没有事件桶");
    CHECK_EQ(-1, s.peakHour, "空输入：peakHour 为 -1");
    CHECK_EQ(0, s.ipCount, "空输入：没有源 IP");

    CHECK_EQ(-1, Stats_Compute(NULL, 1, &s), "logs=NULL 但 count>0 报错");
    CHECK_EQ(-1, Stats_Compute(logs, -1, &s), "count<0 报错");
    CHECK_EQ(-1, Stats_Compute(logs, 1, NULL), "out=NULL 报错");
}

static void TestSingleRecord(void)
{
    LogEntry log = MakeLog(4624, "user", "2026/10/28-10:00:00", "10.0.0.1");
    StatsSummary s;

    CHECK_EQ(0, Stats_Compute(&log, 1, &s), "单条记录：统计成功");
    CHECK_EQ(1, s.total, "单条记录：total 为 1");
    CHECK_EQ(1, s.eventKindCount, "单条记录：一个事件桶");
    CHECK_EQ(4624, s.events[0].eventId, "单条记录：EventID 4624");
    CHECK_EQ(1, s.events[0].count, "单条记录：计数为 1");
    CHECK_EQ(1, s.ipCount, "单条记录：Top IP 一条");
    CHECK_STR("10.0.0.1", s.ips[0].label, "单条记录：IP 标签正确");
    CHECK_EQ(1, s.ips[0].count, "单条记录：IP 计数为 1");
    CHECK_EQ(1, s.userCount, "单条记录：Top 用户名一条");
    CHECK_STR("user", s.users[0].label, "单条记录：用户名标签正确");
    CHECK_EQ(1, s.hours[10], "单条记录：10 点桶为 1");
    CHECK_EQ(1, s.hourKnown, "单条记录：时间可解析 1 条");
    CHECK_EQ(0, s.hourUnknown, "单条记录：无解析失败");
    CHECK_EQ(10, s.peakHour, "单条记录：峰值小时为 10");
}

static void TestEventDistribution(void)
{
    LogEntry logs[7];
    StatsSummary s;

    logs[0] = MakeLog(4624, "u1", "2026/10/28-01:00:00", "1.1.1.1");
    logs[1] = MakeLog(4624, "u1", "2026/10/28-01:00:00", "1.1.1.1");
    logs[2] = MakeLog(4624, "u1", "2026/10/28-01:00:00", "1.1.1.1");
    logs[3] = MakeLog(4625, "u2", "2026/10/28-02:00:00", "2.2.2.2");
    logs[4] = MakeLog(4625, "u2", "2026/10/28-02:00:00", "2.2.2.2");
    logs[5] = MakeLog(4672, "SYSTEM", "2026/10/28-03:00:00", "-");
    logs[6] = MakeLog(4720, "backdoor", "2026/10/28-04:00:00", "-");

    CHECK_EQ(0, Stats_Compute(logs, 7, &s), "事件分布：统计成功");
    CHECK_EQ(4, s.eventKindCount, "事件分布：4 种 EventID");
    CHECK_EQ(4624, s.events[0].eventId, "事件分布：第一名 4624");
    CHECK_EQ(3, s.events[0].count, "事件分布：4624 计数 3");
    CHECK_EQ(4625, s.events[1].eventId, "事件分布：第二名 4625");
    CHECK_EQ(2, s.events[1].count, "事件分布：4625 计数 2");
    CHECK_EQ(4672, s.events[2].eventId, "事件分布：并列按 EventID 升序（4672）");
    CHECK_EQ(4720, s.events[3].eventId, "事件分布：并列按 EventID 升序（4720）");
    CHECK_EQ(0, s.otherEventCount, "事件分布：没有溢出桶");
}

static void TestEventOverflow(void)
{
    LogEntry logs[9];
    StatsSummary s;
    int i;

    for (i = 0; i < 9; i++) {
        logs[i] = MakeLog(1000 + i, "user", "2026/10/28-01:00:00", "1.1.1.1");
    }

    CHECK_EQ(0, Stats_Compute(logs, 9, &s), "事件溢出：统计成功");
    CHECK_EQ(STATS_EVENT_MAX, s.eventKindCount, "事件溢出：桶数到达上限");
    CHECK_EQ(1, s.otherEventCount, "事件溢出：超出的 1 条单独计数");
    CHECK_EQ(9, s.total, "事件溢出：total 仍是 9");
}

static void TestIpRanking(void)
{
    LogEntry logs[8];
    StatsSummary s;

    /* 1.1.1.1 x3；2.2.2.2 x2；3.3.3.3 x1；"-"/空 不参与 */
    logs[0] = MakeLog(4625, "u", "2026/10/28-01:00:00", "1.1.1.1");
    logs[1] = MakeLog(4625, "u", "2026/10/28-01:00:00", "1.1.1.1");
    logs[2] = MakeLog(4625, "u", "2026/10/28-01:00:00", "1.1.1.1");
    logs[3] = MakeLog(4625, "u", "2026/10/28-01:00:00", "2.2.2.2");
    logs[4] = MakeLog(4625, "u", "2026/10/28-01:00:00", "2.2.2.2");
    logs[5] = MakeLog(4625, "u", "2026/10/28-01:00:00", "3.3.3.3");
    logs[6] = MakeLog(4625, "u", "2026/10/28-01:00:00", "-");
    logs[7] = MakeLog(4625, "u", "2026/10/28-01:00:00", "");

    CHECK_EQ(0, Stats_Compute(logs, 8, &s), "IP 排行：统计成功");
    CHECK_EQ(3, s.ipCount, "IP 排行：3 个可用 IP（排除 - 与空串）");
    CHECK_STR("1.1.1.1", s.ips[0].label, "IP 排行：第一名 1.1.1.1");
    CHECK_EQ(3, s.ips[0].count, "IP 排行：1.1.1.1 计数 3");
    CHECK_STR("2.2.2.2", s.ips[1].label, "IP 排行：第二名 2.2.2.2");
    CHECK_EQ(2, s.ips[1].count, "IP 排行：2.2.2.2 计数 2");
    CHECK_STR("3.3.3.3", s.ips[2].label, "IP 排行：第三名 3.3.3.3");
}

static void TestTopLimit(void)
{
    LogEntry logs[7];
    StatsSummary s;
    int i;

    /* 7 个不同 IP 各 1 次：并列时按字典序，只留前 5 个 */
    for (i = 0; i < 7; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.0.0.%d", i + 1);
        logs[i] = MakeLog(4624, "u", "2026/10/28-01:00:00", ip);
    }

    CHECK_EQ(0, Stats_Compute(logs, 7, &s), "Top 上限：统计成功");
    CHECK_EQ(STATS_TOP_N, s.ipCount, "Top 上限：只保留 5 个 IP");
    CHECK_STR("10.0.0.1", s.ips[0].label, "Top 上限：第一名 10.0.0.1");
    CHECK_STR("10.0.0.5", s.ips[4].label, "Top 上限：第五名 10.0.0.5");
}

static void TestUserAggregation(void)
{
    LogEntry logs[5];
    StatsSummary s;

    logs[0] = MakeLog(4625, "DOMAIN\\admin", "2026/10/28-01:00:00", "1.1.1.1");
    logs[1] = MakeLog(4625, "admin", "2026/10/28-01:00:00", "1.1.1.1");
    logs[2] = MakeLog(4625, "Admin", "2026/10/28-01:00:00", "1.1.1.1");
    logs[3] = MakeLog(4625, "-", "2026/10/28-01:00:00", "-");
    logs[4] = MakeLog(4625, "", "2026/10/28-01:00:00", "-");

    CHECK_EQ(0, Stats_Compute(logs, 5, &s), "用户名聚合：统计成功");
    CHECK_EQ(1, s.userCount, "用户名聚合：只有一个账户（- 与空串被排除）");
    CHECK_STR("admin", s.users[0].label, "用户名聚合：去掉 DOMAIN\\ 前缀");
    CHECK_EQ(3, s.users[0].count, "用户名聚合：admin 计数 3");
}

static void TestHourHistogram(void)
{
    LogEntry logs[5];
    StatsSummary s;

    logs[0] = MakeLog(4624, "u", "2026/10/28-00:00:00", "1.1.1.1");
    logs[1] = MakeLog(4624, "u", "2026/10/28-05:59:59", "1.1.1.1");
    logs[2] = MakeLog(4624, "u", "2026/10/28-23:00:00", "1.1.1.1");
    logs[3] = MakeLog(4624, "u", "", "1.1.1.1");
    logs[4] = MakeLog(4624, "u", "2026/10/28", "1.1.1.1");

    CHECK_EQ(0, Stats_Compute(logs, 5, &s), "小时直方图：统计成功");
    CHECK_EQ(1, s.hours[0], "小时直方图：00 点桶为 1");
    CHECK_EQ(1, s.hours[5], "小时直方图：05 点桶为 1");
    CHECK_EQ(1, s.hours[23], "小时直方图：23 点桶为 1");
    CHECK_EQ(3, s.hourKnown, "小时直方图：可解析 3 条");
    CHECK_EQ(2, s.hourUnknown, "小时直方图：解析失败 2 条，不算 0 点");
    CHECK_EQ(0, s.peakHour, "小时直方图：并列取最小小时 0");
}

static void TestPeakHour(void)
{
    LogEntry logs[4];
    StatsSummary s;

    logs[0] = MakeLog(4624, "u", "2026/10/28-14:00:00", "1.1.1.1");
    logs[1] = MakeLog(4624, "u", "2026/10/28-14:30:00", "1.1.1.1");
    logs[2] = MakeLog(4624, "u", "2026/10/28-09:00:00", "1.1.1.1");
    logs[3] = MakeLog(4624, "u", "2026/10/28-09:30:00", "1.1.1.1");

    CHECK_EQ(0, Stats_Compute(logs, 4, &s), "峰值：统计成功");
    /* 9 点和 14 点各 2 条，取较小的小时 */
    CHECK_EQ(2, s.hours[9], "峰值：09 点桶为 2");
    CHECK_EQ(2, s.hours[14], "峰值：14 点桶为 2");
    CHECK_EQ(9, s.peakHour, "峰值：并列取较小的小时 9");
}

static void TestAllTimesInvalid(void)
{
    LogEntry logs[2];
    StatsSummary s;

    logs[0] = MakeLog(4624, "u", "", "1.1.1.1");
    logs[1] = MakeLog(4624, "u", "garbage", "1.1.1.1");

    CHECK_EQ(0, Stats_Compute(logs, 2, &s), "时间全坏：统计成功");
    CHECK_EQ(0, s.hourKnown, "时间全坏：可解析 0 条");
    CHECK_EQ(2, s.hourUnknown, "时间全坏：失败 2 条");
    CHECK_EQ(-1, s.peakHour, "时间全坏：peakHour 为 -1");
}

static void TestInputUnchanged(void)
{
    LogEntry logs[2];
    LogEntry copy[2];
    StatsSummary s;

    logs[0] = MakeLog(4624, "u1", "2026/10/28-10:00:00", "1.1.1.1");
    logs[1] = MakeLog(4625, "u2", "2026/10/28-11:00:00", "2.2.2.2");
    memcpy(copy, logs, sizeof(logs));

    CHECK_EQ(0, Stats_Compute(logs, 2, &s), "输入不变：统计成功");
    CHECK_EQ(0, memcmp(copy, logs, sizeof(logs)), "输入不变：统计不修改原始记录");
    CHECK_EQ(2, s.total, "输入不变：total 为 2");
}

static void TestEventNames(void)
{
    CHECK_STR("登录成功", Stats_EventName(4624), "事件名：4624 登录成功");
    CHECK_STR("登录失败", Stats_EventName(4625), "事件名：4625 登录失败");
    CHECK_STR("特权分配", Stats_EventName(4672), "事件名：4672 特权分配");
    CHECK_STR("创建账户", Stats_EventName(4720), "事件名：4720 创建账户");
    CHECK_STR("其它", Stats_EventName(9999), "事件名：未知 ID 归为其它");
}

int main(void)
{
    TestConsoleUtf8();
    TestParamErrors();
    TestSingleRecord();
    TestEventDistribution();
    TestEventOverflow();
    TestIpRanking();
    TestTopLimit();
    TestUserAggregation();
    TestHourHistogram();
    TestPeakHour();
    TestAllTimesInvalid();
    TestInputUnchanged();
    TestEventNames();

    printf("\n%d checks, %d failed.\n", g_total, g_failed);
    if (g_failed == 0) {
        printf("All stats tests passed!\n");
        return 0;
    }
    return 1;
}
