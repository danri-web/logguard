#ifndef STATS_H
#define STATS_H

#include "log_entry.h"

/* 统计面板的展示上限 */
#define STATS_TOP_N      5      /* Top 源 IP / Top 用户名各展示几条 */
#define STATS_HOURS     24      /* 按小时直方图的分桶数（本地时间） */
#define STATS_EVENT_MAX  8      /* 事件分布最多保留几种 EventID，其余计入 otherEventCount */

/* 一种 EventID 的出现次数 */
typedef struct {
    int eventId;
    int count;
} StatsEventBucket;

/* 一个聚合标签（源 IP 或用户名）的出现次数 */
typedef struct {
    char label[LOG_USER_LEN];
    int  count;
} StatsRankItem;

/*
 * 一次统计的完整结果。
 * 约定：
 *   - events 按次数降序、次数相同按 EventID 升序排列；
 *   - ips / users 已排除空串与 "-"（Windows 的“无来源/无账户”占位符），
 *     标签按 ASCII 大小写无关聚合（展示首次出现的写法），
 *     按次数降序、次数相同按标签字典序升序，只保留前 STATS_TOP_N 个；
 *   - users 的标签是去掉 DOMAIN\ 前缀后的账户名；
 *   - hours 只统计时间可解析的记录，hourUnknown 为解析失败条数；
 *   - peakHour 为次数最多的小时（并列取最小的小时），无可用时间时为 -1。
 */
typedef struct {
    int total;                            /* 参与统计的记录数 */

    StatsEventBucket events[STATS_EVENT_MAX];
    int eventKindCount;                   /* events 中有效的桶数 */
    int otherEventCount;                  /* 超出 STATS_EVENT_MAX 的记录数 */

    StatsRankItem ips[STATS_TOP_N];
    int ipCount;

    StatsRankItem users[STATS_TOP_N];
    int userCount;

    int hours[STATS_HOURS];
    int hourKnown;
    int hourUnknown;
    int peakHour;
} StatsSummary;

/*
 * 统计一组日志。logs 可以为 NULL（count == 0 时）。
 * 返回 0 成功，-1 参数非法或内存不足。
 * 纯 C99，不依赖 Win32，方便单元测试。
 */
int Stats_Compute(const LogEntry *logs, int count, StatsSummary *out);

#endif /* STATS_H */
