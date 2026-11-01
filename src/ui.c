#include <stdio.h>
#include "ui.h"
#include "version.h"

void PrintWelcome(void)
{
    printf("============================================================\n");
    printf("       欢迎使用 LogGuard 终端安全日志分析系统 V%s\n", LOGUARD_VERSION);
    printf("       数据源：本机 Security 事件日志 / .evtx 文件\n");
    printf("============================================================\n");
}

/* 直接遍历菜单数组打印，再也不用 if (option == 1) 了 */
void PrintMenu(const MenuItem *menu, int menuSize, const char *sourceDesc)
{
    printf("\n============================================================\n");
    printf("                       LogGuard v%s\n", LOGUARD_VERSION);
    printf("============================================================\n");
    printf("   数据源：%s\n", sourceDesc ? sourceDesc : "-");
    printf("------------------------------------------------------------\n");
    for (int i = 0; i < menuSize; i++) {
        printf("   %d. %s\n", menu[i].id, menu[i].name);
    }
    printf("   0. 退出\n");
    printf("============================================================\n");
    printf("请选择：");
}

void PrintHeader(const MenuItem *item)
{
    printf("\n------------------------------------------------------------\n");
    printf("  %d. %s\n", item->id, item->name);
    printf("------------------------------------------------------------\n");
    if (item->desc) {
        printf("  说明：%s\n", item->desc);
    }
}

void PrintLogEntry(const LogEntry *log, int index)
{
    printf("\n+----------------------------------------------------------\n");
    printf("| [%02d] EventId     : %d\n", index, log->eventId);
    printf("|      DateAndTime : %s\n", log->dateAndTime);
    printf("|      UserName    : %s\n", log->userName);
    printf("|      LogonType   : %d\n", log->logOnType);
    printf("|      Description : %s\n", log->description);
    printf("|      SourceIP    : %s\n", log->sourceIP);
    printf("|      ProcessName : %s\n", log->processName[0] ? log->processName : "-");
    printf("+----------------------------------------------------------\n");
}

/* 用 # 画最多 width 格的横条；非零至少画 1 格 */
static void PrintBar(int value, int maxValue, int width)
{
    int n = 0;
    int i;

    if (value > 0 && maxValue > 0) {
        n = (value * width + maxValue - 1) / maxValue; /* 向上取整，小值也看得见 */
        if (n < 1) n = 1;
        if (n > width) n = width;
    }
    for (i = 0; i < n; i++) putchar('#');
}

/* 统计面板：事件分布、Top 源 IP、Top 用户名、按小时直方图 */
void PrintStatsPanel(const StatsSummary *summary, const char *title,
                     const char *sourceDesc)
{
    int i;
    int maxCount;

    if (summary == NULL) return;

    printf("\n------------------------------------------------------------\n");
    printf("  统计面板：%s\n", title ? title : "数据总览");
    printf("------------------------------------------------------------\n");
    printf("  数据源：%s\n", sourceDesc ? sourceDesc : "-");
    printf("  样本：共 %d 条记录\n", summary->total);

    /* ---------------- 事件分布 ---------------- */
    printf("\n  [事件分布]\n");
    if (summary->eventKindCount == 0) {
        printf("    （没有事件数据）\n");
    } else {
        maxCount = 0;
        for (i = 0; i < summary->eventKindCount; i++) {
            if (summary->events[i].count > maxCount) maxCount = summary->events[i].count;
        }
        for (i = 0; i < summary->eventKindCount; i++) {
            double pct = (summary->total > 0)
                       ? (double)summary->events[i].count * 100.0 / (double)summary->total
                       : 0.0;
            printf("    %d  %s  %d 条  %.1f%%  ",
                   summary->events[i].eventId,
                   Stats_EventName(summary->events[i].eventId),
                   summary->events[i].count, pct);
            PrintBar(summary->events[i].count, maxCount, 20);
            printf("\n");
        }
        if (summary->otherEventCount > 0) {
            printf("    其它 EventID 合计 %d 条（明细不展开）\n", summary->otherEventCount);
        }
    }

    /* ---------------- Top 源 IP ---------------- */
    printf("\n  [Top 源 IP]\n");
    if (summary->ipCount == 0) {
        printf("    （没有可用源 IP：本机登录或该事件不带 IpAddress）\n");
    } else {
        maxCount = summary->ips[0].count;
        for (i = 0; i < summary->ipCount; i++) {
            printf("    %d. %s  %d 次  ", i + 1, summary->ips[i].label,
                   summary->ips[i].count);
            PrintBar(summary->ips[i].count, maxCount, 24);
            printf("\n");
        }
    }

    /* ---------------- Top 用户名 ---------------- */
    printf("\n  [Top 用户名]\n");
    if (summary->userCount == 0) {
        printf("    （没有可用用户名）\n");
    } else {
        maxCount = summary->users[0].count;
        for (i = 0; i < summary->userCount; i++) {
            printf("    %d. %s  %d 次  ", i + 1, summary->users[i].label,
                   summary->users[i].count);
            PrintBar(summary->users[i].count, maxCount, 24);
            printf("\n");
        }
    }

    /* ---------------- 按小时直方图 ---------------- */
    printf("\n  [按小时直方图]\n");
    if (summary->hourKnown == 0) {
        printf("    （时间字段缺失或无法解析，直方图跳过）\n");
    } else {
        maxCount = 0;
        for (i = 0; i < STATS_HOURS; i++) {
            if (summary->hours[i] > maxCount) maxCount = summary->hours[i];
        }
        for (i = 0; i < STATS_HOURS; i++) {
            printf("    %02d 时 | ", i);
            PrintBar(summary->hours[i], maxCount, 36);
            printf(" %d", summary->hours[i]);
            if (i == summary->peakHour) printf("  <- 峰值");
            printf("\n");
        }
        if (summary->hourUnknown > 0) {
            printf("    另有 %d 条时间无法解析，未计入\n", summary->hourUnknown);
        }
    }
}

void PrintFooter(const MenuItem *item, int count)
{
    printf("\n  查询完成：%s，共 %d 条记录。\n", item ? item->name : "", count);
}

int ReadOption(int *option)
{
    int ch;
    if (scanf("%d", option) != 1) {
        ch = getchar();
        while (ch != '\n' && ch != EOF) ch = getchar();
        if (ch == EOF) return 0;
        PrintError("输入无效，请输入菜单中的数字。");
        return -1;
    }
    return 1;
}

void PrintInfo(const char *msg)
{
    printf("\n  %s\n", msg);
}

void PrintError(const char *msg)
{
    printf("\n  [错误] %s\n", msg);
}