#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <wchar.h>
#include <windows.h>

#include "log_entry.h"
#include "log_reader.h"
#include "filter.h"
#include "ui.h"
#include "export.h"
#include "cli.h"
#include "version.h"

/* 老版本 SDK 头文件里可能没有这个常量 */
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

/* 命令行文件路径上限（宽字符数） */
#define LOGUARD_PATH_MAX 512

static LogEntry g_logs[LOG_MAX_COUNT];
static int      g_logCount = 0;

/* 空串表示数据源是本机 Security 通道；否则是 .evtx 文件路径 */
static wchar_t  g_sourcePath[LOGUARD_PATH_MAX];

/* 是否真的能输出 ANSI 颜色（重定向到文件时为 0） */
static int      g_colorEnabled = 0;

/* 定义菜单列表（表驱动核心） */
static const MenuItem g_menuList[] = {
    {1, "浏览全部登录日志", "显示最近 20 条 4624/4625 记录", 20, 0},
    {2, "登录失败检测",     "筛选所有 4625 登录失败记录", 100, 0},
    {3, "管理员登录检测",   "筛选针对 admin 账户的 4625 记录", 100, 0},
    {4, "高频 IP 爆破检测", "分析最近 500 条日志中失败次数 >= 3 的 IP", 500, 1},
    {5, "凌晨异常登录检测", "筛选 00:00-05:59 之间的 4624 成功登录记录", 500, 0},
    {6, "系统特权分配监控", "监控 4672 特权分配事件 (防提权)", 100, 0},
    {7, "隐蔽后门账号监控", "监控 4720 创建账户事件 (防留后门)", 100, 0},
    {8, "切换数据源（本机 / .evtx 文件）", "分析导出的 .evtx 文件，或切回本机 Security", 0, 0}
};
static const int g_menuSize = sizeof(g_menuList) / sizeof(g_menuList[0]);

static const char *AnsiRed(void)   { return g_colorEnabled ? "\033[1;31m" : ""; }
static const char *AnsiGreen(void) { return g_colorEnabled ? "\033[1;32m" : ""; }
static const char *AnsiReset(void) { return g_colorEnabled ? "\033[0m" : ""; }

/* 打开 ANSI 转义序列支持；失败（如重定向到文件）就退化为纯文本 */
static void EnableAnsiColor(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;

    g_colorEnabled = 0;
    if (hOut == INVALID_HANDLE_VALUE || hOut == NULL) return;
    if (!GetConsoleMode(hOut, &mode)) return;
    if (!SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) return;
    g_colorEnabled = 1;
}

/* 当前进程是否已提升为管理员 */
static int IsElevated(void)
{
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation;
    DWORD size = 0;
    int elevated = 0;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (GetTokenInformation(token, TokenElevation, &elevation,
                                sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated ? 1 : 0;
        }
        CloseHandle(token);
    }
    return elevated;
}

/* 宽字符转 UTF-8，失败时输出空串 */
static void WideToUtf8(const wchar_t *src, char *dst, size_t dstLen)
{
    int n;
    if (!dst || dstLen == 0) return;
    dst[0] = '\0';
    if (!src) return;

    n = WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, (int)dstLen, NULL, NULL);
    if (n <= 0) dst[0] = '\0';
}

/* 数据源描述：本机通道，或 "文件 <路径>" */
static void DescribeSource(const wchar_t *target, int isFile, char *buf, size_t len)
{
    char pathUtf8[LOGUARD_PATH_MAX * 4] = {0};

    if (!buf || len == 0) return;
    if (!isFile) {
        snprintf(buf, len, "本机 Security 通道");
        return;
    }
    WideToUtf8(target, pathUtf8, sizeof(pathUtf8));
    snprintf(buf, len, "文件 %s", pathUtf8);
}

/* 获取对应的过滤函数 */
static FilterFunc GetFilterFunc(int option) {
    switch (option) {
        case 1: return Filter_All;
        case 2: return Filter_FailedLogin;
        case 3: return Filter_AdminFailed;
        case 5: return Filter_NightLogin;
        case 6: return Filter_Privilege;
        case 7: return Filter_AccountCreated;
        default: return Filter_All;
    }
}

/* 按菜单项选择 XPath 粗筛条件 */
static const wchar_t *XpathForId(int id)
{
    if (id == 6) return L"*[System[(EventID=4672)]]";
    if (id == 7) return L"*[System[(EventID=4720)]]";
    return L"*[System[(EventID=4624 or EventID=4625)]]";
}

static const MenuItem *FindMenuItem(int id)
{
    int i;
    for (i = 0; i < g_menuSize; i++) {
        if (g_menuList[i].id == id) return &g_menuList[i];
    }
    return NULL;
}

/* 交互模式：询问并切换数据源 */
static void PromptForSource(void)
{
    char line[LOGUARD_PATH_MAX * 4];
    wchar_t wide[LOGUARD_PATH_MAX];
    char *start;
    size_t len;
    int ch;
    int n;
    DWORD attr;

    printf("\n  输入 .evtx 文件路径（直接回车取消，输入 - 切回本机 Security）：\n  > ");

    /* scanf("%d") 会留下换行符，先把这一行剩下的内容吃掉 */
    while ((ch = getchar()) != '\n' && ch != EOF) { }

    if (!fgets(line, sizeof(line), stdin)) return;

    len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                       line[len - 1] == ' '  || line[len - 1] == '\t')) {
        line[--len] = '\0';
    }
    start = line;
    while (*start == ' ' || *start == '\t') start++;

    /* 从资源管理器拖进控制台的路径常带双引号 */
    if (start[0] == '"') {
        start++;
        len = strlen(start);
        if (len > 0 && start[len - 1] == '"') start[len - 1] = '\0';
    }

    if (*start == '\0') {
        PrintInfo("未改变数据源。");
        return;
    }
    if (strcmp(start, "-") == 0) {
        g_sourcePath[0] = L'\0';
        PrintInfo("已切回本机 Security 通道。");
        return;
    }

    n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            start, -1, wide, LOGUARD_PATH_MAX);
    if (n <= 0) {
        n = MultiByteToWideChar(CP_ACP, 0, start, -1, wide, LOGUARD_PATH_MAX);
    }
    if (n <= 0) {
        PrintError("路径转换失败，请检查控制台编码。");
        return;
    }

    attr = GetFileAttributesW(wide);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        PrintError("文件不存在或不是普通文件。");
        return;
    }

    wcsncpy(g_sourcePath, wide, LOGUARD_PATH_MAX - 1);
    g_sourcePath[LOGUARD_PATH_MAX - 1] = L'\0';

    {
        char desc[LOGUARD_PATH_MAX * 4 + 16];
        DescribeSource(g_sourcePath, 1, desc, sizeof(desc));
        printf("  已切换数据源：%s\n", desc);
    }
}

/* 聚合查询：爆破检测。把命中的记录同时收进 matched，便于导出。 */
static int RunBruteForceQuery(LogEntry *matched, int maxMatched)
{
    typedef struct { char ip[LOG_IP_LEN]; int failCount; } IpStat;
    IpStat *stats;
    int statCount = 0, i, j;
    int count = 0;

    if (g_logCount <= 0) return 0;

    /* 上限就是本次读到的日志条数，不设固定坑位，也不会静默丢 IP */
    stats = (IpStat *)calloc((size_t)g_logCount, sizeof(IpStat));
    if (!stats) {
        PrintError("内存不足，无法完成爆破统计。");
        return -1;
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

    {
        int riskyCount = 0;
        printf("\n  [告警] 发现以下高频失败 IP：\n");
        for (j = 0; j < statCount; j++) {
            if (stats[j].failCount >= 3) {
                printf("  %s>> 高危 IP: %-15s 失败次数: %d 次%s\n",
                       AnsiRed(), stats[j].ip, stats[j].failCount, AnsiReset());
                riskyCount++;
            }
        }

        if (riskyCount == 0) {
            PrintInfo("暂无高危 IP (阈值: 失败 >= 3 次)。");
            free(stats);
            return 0;
        }

        for (i = 0; i < g_logCount; i++) {
            if (g_logs[i].eventId != 4625) continue;
            for (j = 0; j < statCount; j++) {
                if (stats[j].failCount >= 3 &&
                    strcmp(stats[j].ip, g_logs[i].sourceIP) == 0) {
                    if (count < maxMatched) matched[count] = g_logs[i];
                    count++;
                    PrintLogEntry(&g_logs[i], count);
                    break;
                }
            }
        }
    }

    free(stats);
    return count;
}

/* 交互模式：询问并导出 */
static void AskAndExport(const LogEntry *matchedLogs, int count)
{
    char ans[10];
    const wchar_t *filename = L"LogGuard_Report.csv";

    if (count <= 0) return;

    printf("\n  是否将本次查询结果导出为 CSV 文件？(y/n): ");
    if (scanf("%9s", ans) == 1) {
        if (ans[0] == 'y' || ans[0] == 'Y') {
            int exported = ExportToCsv(matchedLogs, count, filename);
            if (exported > 0) {
                printf("  %s>> 成功导出 %d 条记录至文件: %s%s\n",
                       AnsiGreen(), exported, "LogGuard_Report.csv", AnsiReset());
            } else {
                PrintError("导出失败，请检查路径和文件写入权限。");
            }
        }
    }
}

/*
 * 执行一次查询：读日志 -> 过滤/聚合 -> 打印 -> 可选导出。
 * 返回 0 成功，1 内存错误，2 读取失败，3 导出失败。
 */
static int ExecuteQuery(const MenuItem *item, const wchar_t *target, int isFile,
                        int maxRead, const wchar_t *exportPath, int askExport)
{
    wchar_t errBuf[256] = {0};
    LogEntry *matched;
    int count = 0;
    int rc = 0;

    if (maxRead <= 0 || maxRead > LOG_MAX_COUNT) maxRead = 100;

    g_logCount = ReadLogs(target, isFile, g_logs, maxRead,
                          XpathForId(item->id), errBuf,
                          sizeof(errBuf) / sizeof(errBuf[0]));

    if (g_logCount < 0) {
        char errMsg[512] = {0};
        char targetUtf8[LOGUARD_PATH_MAX * 4] = {0};
        char outMsg[4096];

        WideToUtf8(errBuf, errMsg, sizeof(errMsg));
        WideToUtf8(target, targetUtf8, sizeof(targetUtf8));

        if (isFile) {
            snprintf(outMsg, sizeof(outMsg), "无法读取文件 \"%s\"！%s",
                     targetUtf8, errMsg);
        } else {
            snprintf(outMsg, sizeof(outMsg), "无法读取 Security 通道！%s（该通道需要管理员权限）",
                     errMsg);
        }
        PrintError(outMsg);
        return 2;
    }

    PrintHeader(item);

    if (g_logCount == 0) {
        PrintInfo(isFile ? "文件中没有读取到日志记录。" : "没有读取到任何日志记录。");
        return 0;
    }

    matched = (LogEntry *)malloc(sizeof(LogEntry) * (size_t)g_logCount);
    if (!matched) {
        PrintError("内存不足，无法保存查询结果。");
        return 1;
    }

    if (item->isAggregate) {
        count = RunBruteForceQuery(matched, g_logCount);
        if (count < 0) {
            free(matched);
            return 1;
        }
    } else {
        FilterFunc filter = GetFilterFunc(item->id);
        int i;
        for (i = 0; i < g_logCount; i++) {
            if (filter(&g_logs[i])) {
                matched[count] = g_logs[i];
                count++;
                PrintLogEntry(&g_logs[i], count);
            }
        }
    }

    if (count == 0) {
        /* 聚合查询已经在统计阶段给过“暂无高危 IP”，这里不再重复 */
        if (!item->isAggregate) PrintInfo("没有符合条件的日志记录。");
    } else {
        PrintFooter(item, count);

        if (exportPath != NULL) {
            char exportUtf8[LOGUARD_PATH_MAX * 4] = {0};
            int exported = ExportToCsv(matched, count, exportPath);
            WideToUtf8(exportPath, exportUtf8, sizeof(exportUtf8));
            if (exported > 0) {
                printf("  %s>> 成功导出 %d 条记录至文件: %s%s\n",
                       AnsiGreen(), exported, exportUtf8, AnsiReset());
            } else {
                PrintError("导出失败，请检查路径和文件写入权限。");
                rc = 3;
            }
        } else if (askExport) {
            AskAndExport(matched, count);
        }
    }

    free(matched);
    return rc;
}

/* 交互模式下一次菜单查询 */
static void RunQuery(const MenuItem *item)
{
    const wchar_t *target = g_sourcePath[0] != L'\0' ? g_sourcePath : L"Security";
    int isFile = g_sourcePath[0] != L'\0';
    ExecuteQuery(item, target, isFile, item->maxRead, NULL, 1);
}

/* 批处理模式：一条命令完成查询和导出 */
static int RunBatch(const CliOptions *opt)
{
    int filterId = opt->filterId > 0 ? opt->filterId : 1;
    const MenuItem *item = FindMenuItem(filterId);
    const wchar_t *target;
    int isFile;
    int limit;
    char desc[LOGUARD_PATH_MAX * 4 + 16];

    if (!item) {
        fprintf(stderr, "错误：未知的过滤规则。\n");
        return 1;
    }

    if (opt->hasFile) {
        target = opt->file;
        isFile = 1;
    } else {
        target = L"Security";
        isFile = 0;
    }

    limit = opt->limit > 0 ? opt->limit : item->maxRead;

    DescribeSource(target, isFile, desc, sizeof(desc));
    printf("%s %s  |  数据源：%s\n", LOGUARD_NAME, LOGUARD_VERSION, desc);

    if (!isFile && !IsElevated()) {
        fprintf(stderr, "提示：当前不是管理员，读取本机 Security 会失败；"
                        "可改用 --file 分析 .evtx。\n");
    }

    return ExecuteQuery(item, target, isFile, limit,
                        opt->hasExport ? opt->exportPath : NULL, 0);
}

static int RunInteractive(void)
{
    int option;
    int ret;

    PrintWelcome();
    if (g_sourcePath[0] == L'\0' && !IsElevated()) {
        printf("\n  [提示] 当前未以管理员身份运行：读取本机 Security 会失败；\n"
               "         可选菜单 8 分析 .evtx 文件，或右键“以管理员身份运行”。\n");
    }

    while (1) {
        char desc[LOGUARD_PATH_MAX * 4 + 16];
        const wchar_t *target = g_sourcePath[0] != L'\0' ? g_sourcePath : L"Security";
        int isFile = g_sourcePath[0] != L'\0';
        const MenuItem *item;

        DescribeSource(target, isFile, desc, sizeof(desc));
        PrintMenu(g_menuList, g_menuSize, desc);

        ret = ReadOption(&option);
        if (ret == 0) break;
        if (ret < 0) continue;
        if (option == 0) break;

        if (option == 8) {
            PromptForSource();
            continue;
        }

        item = FindMenuItem(option);
        if (!item) {
            PrintError("输入无效，请重新选择。");
            continue;
        }
        RunQuery(item);
    }

    printf("\nLogGuard 已退出，感谢使用。\n");
    return 0;
}

int main(void)
{
    int exitCode = 0;
    int wargc = 0;
    wchar_t **wargv;
    CliOptions opt;

    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);
    EnableAnsiColor();

    wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    if (!wargv) {
        return RunInteractive();
    }

    if (Cli_Parse(wargc, wargv, &opt) != 0) {
        fprintf(stderr, "错误：%s\n\n", opt.error ? opt.error : "参数解析失败");
        Cli_PrintUsage();
        LocalFree(wargv);
        return 1;
    }

    if (opt.noColor) g_colorEnabled = 0;

    if (opt.help) {
        Cli_PrintUsage();
        LocalFree(wargv);
        return 0;
    }
    if (opt.version) {
        printf("%s %s\n", LOGUARD_NAME, LOGUARD_VERSION);
        LocalFree(wargv);
        return 0;
    }

    if (opt.batch) {
        exitCode = RunBatch(&opt);
    } else {
        exitCode = RunInteractive();
    }

    LocalFree(wargv);
    return exitCode;
}
