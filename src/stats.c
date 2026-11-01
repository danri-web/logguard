#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stats.h"
#include "filter.h"

/* 有长度上限的字符串拷贝，保证结果以 '\0' 结尾 */
static void CopyLabel(char *dst, size_t dstLen, const char *src)
{
    size_t n;
    if (dst == NULL || dstLen == 0) return;
    if (src == NULL) { dst[0] = '\0'; return; }
    n = strlen(src);
    if (n >= dstLen) n = dstLen - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ASCII 大小写无关比较：同一个账户/同一个 IPv6 地址可能大小写不同 */
static int EqualsIgnoreCase(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

/* 在 items[0..*used) 里找标签（忽略大小写），找到就 +1，找不到就追加 */
static void AddOrIncrement(StatsRankItem *items, int *used, const char *label)
{
    int i;

    for (i = 0; i < *used; i++) {
        if (EqualsIgnoreCase(items[i].label, label)) {
            items[i].count++;
            return;
        }
    }

    CopyLabel(items[*used].label, sizeof(items[*used].label), label);
    items[*used].count = 1;
    (*used)++;
}

/* 次数降序；次数相同按 EventID 升序，保证输出稳定 */
static int CompareEvent(const void *a, const void *b)
{
    const StatsEventBucket *x = (const StatsEventBucket *)a;
    const StatsEventBucket *y = (const StatsEventBucket *)b;

    if (x->count != y->count) return (x->count < y->count) ? 1 : -1;
    if (x->eventId != y->eventId) return (x->eventId < y->eventId) ? -1 : 1;
    return 0;
}

/* 次数降序；次数相同按标签字典序升序，保证输出稳定 */
static int CompareRank(const void *a, const void *b)
{
    const StatsRankItem *x = (const StatsRankItem *)a;
    const StatsRankItem *y = (const StatsRankItem *)b;

    if (x->count != y->count) return (x->count < y->count) ? 1 : -1;
    return strcmp(x->label, y->label);
}

int Stats_Compute(const LogEntry *logs, int count, StatsSummary *out)
{
    StatsRankItem *ips = NULL;
    StatsRankItem *users = NULL;
    int ipUsed = 0;
    int userUsed = 0;
    int i;
    int h;

    if (out == NULL || count < 0) return -1;
    if (count > 0 && logs == NULL) return -1;

    memset(out, 0, sizeof(*out));
    out->peakHour = -1;
    if (count == 0) return 0;

    /* 最坏情况每条记录一个不同的标签，按 count 分配就够了 */
    ips = (StatsRankItem *)calloc((size_t)count, sizeof(*ips));
    users = (StatsRankItem *)calloc((size_t)count, sizeof(*users));
    if (ips == NULL || users == NULL) {
        free(ips);
        free(users);
        return -1;
    }

    for (i = 0; i < count; i++) {
        const LogEntry *log = &logs[i];
        const char *account;
        int found = 0;
        int j;

        out->total++;

        /* 事件分布 */
        for (j = 0; j < out->eventKindCount; j++) {
            if (out->events[j].eventId == log->eventId) {
                out->events[j].count++;
                found = 1;
                break;
            }
        }
        if (!found) {
            if (out->eventKindCount < STATS_EVENT_MAX) {
                out->events[out->eventKindCount].eventId = log->eventId;
                out->events[out->eventKindCount].count = 1;
                out->eventKindCount++;
            } else {
                out->otherEventCount++;
            }
        }

        /* Top 源 IP：本机登录等场景的 "-" 不是真实来源，不参与 */
        if (Filter_HasSourceIp(log->sourceIP)) {
            AddOrIncrement(ips, &ipUsed, log->sourceIP);
        }

        /* Top 用户名：去掉 DOMAIN\ 前缀后再聚合，避免同一账户被拆成两条 */
        account = Filter_AccountName(log->userName);
        if (account[0] != '\0' && strcmp(account, "-") != 0) {
            AddOrIncrement(users, &userUsed, account);
        }

        /* 按小时直方图；时间解析失败单独计数，不当成 0 点 */
        h = Filter_ParseHour(log->dateAndTime);
        if (h >= 0 && h < STATS_HOURS) {
            out->hours[h]++;
            out->hourKnown++;
        } else {
            out->hourUnknown++;
        }
    }

    qsort(out->events, (size_t)out->eventKindCount, sizeof(out->events[0]), CompareEvent);

    qsort(ips, (size_t)ipUsed, sizeof(ips[0]), CompareRank);
    out->ipCount = (ipUsed < STATS_TOP_N) ? ipUsed : STATS_TOP_N;
    memcpy(out->ips, ips, sizeof(out->ips[0]) * (size_t)out->ipCount);

    qsort(users, (size_t)userUsed, sizeof(users[0]), CompareRank);
    out->userCount = (userUsed < STATS_TOP_N) ? userUsed : STATS_TOP_N;
    memcpy(out->users, users, sizeof(out->users[0]) * (size_t)out->userCount);

    if (out->hourKnown > 0) {
        int best = 0;
        for (h = 1; h < STATS_HOURS; h++) {
            if (out->hours[h] > out->hours[best]) best = h;
        }
        out->peakHour = best;
    }

    free(ips);
    free(users);
    return 0;
}
