#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <windows.h>

#include "log_entry.h"
#include "log_reader.h"
#include "filter.h"
#include "ui.h"
#include "export.h" /* 引入导出模块 */

/* 老版本 SDK 头文件里可能没有这个常量 */
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

static LogEntry g_logs[1024];
static int      g_logCount = 0;

/* 定义菜单列表（表驱动核心） */
static const MenuItem g_menuList[] = {
    {1, "浏览全部登录日志", "显示最近 20 条 4624/4625 记录", 20, 0},
    {2, "登录失败检测",     "筛选所有 4625 登录失败记录", 100, 0},
    {3, "管理员登录检测",   "筛选针对 admin 账户的 4625 记录", 100, 0},
    {4, "高频 IP 爆破检测", "分析最近 500 条日志中失败次数 >= 3 的 IP", 500, 1},
    {5, "凌晨异常登录检测", "筛选 00:00-05:59 之间的 4624 成功登录记录", 500, 0},
    {6, "系统特权分配监控", "监控 4672 特权分配事件 (防提权)", 100, 0}, // 新增
    {7, "隐蔽后门账号监控", "监控 4720 创建账户事件 (防留后门)", 100, 0}  // 新增
};
static const int g_menuSize = sizeof(g_menuList) / sizeof(g_menuList[0]);

/* 获取对应的过滤函数 */
static FilterFunc GetFilterFunc(int option) {
    switch (option) {
        case 1: return Filter_All;
        case 2: return Filter_FailedLogin;
        case 3: return Filter_AdminFailed;
        case 5: return Filter_NightLogin;
        case 6: return Filter_Privilege;       // 新增
        case 7: return Filter_AccountCreated;  // 新增
        default: return Filter_All;
    }
}

/* 打开 ANSI 转义序列支持；否则普通控制台会把颜色码原样打印出来 */
static void EnableAnsiColor(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (hOut == INVALID_HANDLE_VALUE || hOut == NULL) return;
    if (!GetConsoleMode(hOut, &mode)) return;
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

/* 聚合查询：爆破检测 */
static void RunBruteForceQuery(void)
{
    typedef struct { char ip[LOG_IP_LEN]; int failCount; } IpStat;
    IpStat *stats;
    int statCount = 0, i, j;

    if (g_logCount <= 0) return;

    /* 上限就是本次读到的日志条数，不需要固定 100 个坑位，也不会静默丢 IP */
    stats = (IpStat *)calloc((size_t)g_logCount, sizeof(IpStat));
    if (!stats) {
        PrintError("内存不足，无法完成爆破统计。");
        return;
    }

    for (i = 0; i < g_logCount; i++) {
        int found = 0;
        if (g_logs[i].eventId != 4625) continue;
        /* 本机失败等场景 sourceIP 为 "-"，不是真实来源，不能参与聚合 */
        if (!Filter_HasSourceIp(g_logs[i].sourceIP)) continue;

        for (j = 0; j < statCount; j++) {
            if (strcmp(stats[j].ip, g_logs[i].sourceIP) == 0) {
                stats[j].failCount++;
                found = 1;
                break;
            }
        }
        if (!found) {
            strncpy(stats[statCount].ip, g_logs[i].sourceIP, sizeof(stats[statCount].ip) - 1);
            stats[statCount].ip[sizeof(stats[statCount].ip) - 1] = '\0';
            stats[statCount].failCount = 1;
            statCount++;
        }
    }

    int riskyCount = 0;
    printf("\n  [告警] 发现以下高频失败 IP：\n");
    for (j = 0; j < statCount; j++) {
        if (stats[j].failCount >= 3) {
            printf("  \033[1;31m>> 高危 IP: %-15s 失败次数: %d 次\033[0m\n", stats[j].ip, stats[j].failCount);
            riskyCount++;
        }
    }

    if (riskyCount == 0) {
        PrintInfo("暂无高危 IP (阈值: 失败 >= 3 次)。");
        free(stats);
        return;
    }

    int printIndex = 0;
    for (i = 0; i < g_logCount; i++) {
        if (g_logs[i].eventId == 4625) {
            for (j = 0; j < statCount; j++) {
                if (stats[j].failCount >= 3 && strcmp(stats[j].ip, g_logs[i].sourceIP) == 0) {
                    printIndex++;
                    PrintLogEntry(&g_logs[i], printIndex);
                    break;
                }
            }
        }
    }

    free(stats);
}

/* 新增：询问并导出 */
static void AskAndExport(const LogEntry *matchedLogs, int count)
{
    if (count <= 0) return;

    printf("\n  是否将本次查询结果导出为 CSV 文件？(y/n): ");
    char ans[10];
    if (scanf("%9s", ans) == 1) {
        if (ans[0] == 'y' || ans[0] == 'Y') {
            const char *filename = "LogGuard_Report.csv";
            int exported = ExportToCsv(matchedLogs, count, filename);
            if (exported > 0) {
                printf("  \033[1;32m>> 成功导出 %d 条记录至文件: %s\033[0m\n", exported, filename);
            } else {
                PrintError("导出失败，请检查是否有文件写入权限。");
            }
        }
    }
}

/* 重构 RunQuery 以收集结果并调用导出 */
static void RunQuery(const MenuItem *item, wchar_t *errBuf, size_t errLen)
{
    const wchar_t *xpath;
    if (item->id == 6) {
        xpath = L"*[System[(EventID=4672)]]";
    } else if (item->id == 7) {
        xpath = L"*[System[(EventID=4720)]]";
    } else {
        xpath = L"*[System[(EventID=4624 or EventID=4625)]]";
    }

    errBuf[0] = L'\0';
    g_logCount = ReadSecurityLogs(g_logs, item->maxRead, xpath, errBuf, errLen);

    if (g_logCount < 0) {
        char errMsg[512] = {0};
        char outMsg[768];

        WideCharToMultiByte(CP_UTF8, 0, errBuf, -1, errMsg, (int)sizeof(errMsg) - 1, NULL, NULL);

        if (errMsg[0] != '\0') {
            snprintf(outMsg, sizeof(outMsg),
                     "无法读取 Security 日志！%s（该通道需要管理员权限）", errMsg);
        } else {
            snprintf(outMsg, sizeof(outMsg),
                     "无法读取 Security 日志！请以管理员身份运行。");
        }
        PrintError(outMsg);
        return;
    }

    PrintHeader(item);

    if (item->isAggregate) {
        if (item->id == 4) RunBruteForceQuery();
        return;
    }

    if (g_logCount == 0) {
        PrintInfo("没有读取到任何日志记录。");
        return;
    }

    FilterFunc filter = GetFilterFunc(item->id);

    /* 准备一个数组用来存放匹配到的结果，方便导出 */
    LogEntry *matched = (LogEntry *)malloc(sizeof(LogEntry) * (size_t)g_logCount);
    if (!matched) {
        PrintError("内存不足，无法保存查询结果。");
        return;
    }
    int count = 0;

    for (int i = 0; i < g_logCount; i++) {
        if (filter(&g_logs[i])) {
            matched[count] = g_logs[i]; // 存入结果数组
            count++;
            PrintLogEntry(&g_logs[i], count);
        }
    }

    if (count == 0) {
        PrintInfo("没有符合条件的日志记录。");
    } else {
        PrintFooter(item, count);
        AskAndExport(matched, count); // 询问是否导出
    }

    free(matched); // 释放临时内存
}

int main(void)
{
    int option;
    int ret;
    wchar_t errBuf[256] = {0};

    SetConsoleOutputCP(65001);
    EnableAnsiColor();
    PrintWelcome();

    while (1) {
        PrintMenu(g_menuList, g_menuSize);
        ret = ReadOption(&option);

        if (ret == 0) break;
        if (ret < 0) continue;
        if (option == 0) break;

        /* 查找选项是否在菜单中 */
        int validOption = 0;
        for (int i = 0; i < g_menuSize; i++) {
            if (g_menuList[i].id == option) {
                RunQuery(&g_menuList[i], errBuf, sizeof(errBuf) / sizeof(errBuf[0]));
                validOption = 1;
                break;
            }
        }

        if (!validOption) {
            PrintError("输入无效，请重新选择。");
        }
    }

    printf("\nLogGuard 已退出，感谢使用。\n");
    return 0;
}
