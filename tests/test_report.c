#include <stdio.h>
#include <string.h>

#include "report.h"
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

#define CHECK_HAS(needle, msg) \
    do { \
        g_total++; \
        if (strstr(g_html, (needle)) == NULL) { \
            g_failed++; \
            printf("[FAIL] %s (missing \"%s\", line %d)\n", (msg), (needle), __LINE__); \
        } else { \
            printf("[PASS] %s\n", (msg)); \
        } \
    } while (0)

#define CHECK_NOT_HAS(needle, msg) \
    do { \
        g_total++; \
        if (strstr(g_html, (needle)) != NULL) { \
            g_failed++; \
            printf("[FAIL] %s (unexpected \"%s\", line %d)\n", (msg), (needle), __LINE__); \
        } else { \
            printf("[PASS] %s\n", (msg)); \
        } \
    } while (0)

static char g_html[65536];

static void CopyStr(char *dst, size_t dstLen, const char *src)
{
    size_t n = strlen(src);
    if (n >= dstLen) n = dstLen - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static LogEntry MakeLog(int eventId, const char *user,
                        const char *time, const char *ip)
{
    LogEntry log;
    memset(&log, 0, sizeof(log));
    log.eventId = eventId;
    CopyStr(log.userName, sizeof(log.userName), user);
    CopyStr(log.dateAndTime, sizeof(log.dateAndTime), time);
    CopyStr(log.sourceIP, sizeof(log.sourceIP), ip);
    CopyStr(log.description, sizeof(log.description), "测试事件");
    return log;
}

/* 渲染到内存，返回 1 成功；0 表示写不出来或参数被拒 */
static int Render(const LogEntry *logs, int count, const char *title, const char *source)
{
    StatsSummary summary;
    ReportMeta meta;
    FILE *fp;
    size_t n;

    if (Stats_Compute(logs, count, &summary) != 0) return 0;

    meta.title = title;
    meta.source = source;
    meta.version = "3.2.0";
    meta.generatedAt = "2026-11-01 13:30:00";

    fp = tmpfile();
    if (fp == NULL) return 0;
    if (Report_WriteHtml(fp, &meta, &summary, logs, count) != 0) {
        fclose(fp);
        return 0;
    }
    fflush(fp);
    fseek(fp, 0, SEEK_SET);
    n = fread(g_html, 1, sizeof(g_html) - 1, fp);
    g_html[n] = '\0';
    fclose(fp);
    return 1;
}

static void TestStructure(void)
{
    LogEntry logs[3];

    logs[0] = MakeLog(4624, "Danri", "2026/10/31-09:12:00", "192.168.1.20");
    logs[1] = MakeLog(4625, "admin", "2026/10/31-02:11:00", "203.0.113.7");
    logs[2] = MakeLog(4625, "admin", "2026/10/31-02:12:00", "203.0.113.7");

    CHECK(Render(logs, 3, "统计面板", "文件 Security.evtx") == 1,
          "渲染成功");
    CHECK_HAS("<!DOCTYPE html>", "有 doctype");
    CHECK_HAS("<html lang=\"zh-CN\">", "有 html lang");
    CHECK_HAS("<meta charset=\"utf-8\">", "声明 UTF-8");
    CHECK_HAS("</html>", "文档闭合");
    CHECK_HAS("<style>", "内嵌 CSS");
    CHECK_HAS("prefers-color-scheme:dark", "支持深色模式");
    CHECK_HAS("LogGuard 安全日志分析报告", "报告标题");
    CHECK_HAS("统计面板", "显示规则名");
    CHECK_HAS("Security.evtx", "显示数据源");
    CHECK_HAS("2026-11-01 13:30:00", "显示生成时间");
    CHECK_HAS("3.2.0", "显示工具版本");
    CHECK_HAS("<table>", "有记录表");
    CHECK_HAS("<th>EventID</th>", "有表头");
    CHECK_HAS("共 <b>3</b> 条记录", "汇总行显示总数");
    CHECK_HAS("4625 登录失败", "事件分布有中文名");
    CHECK_HAS("66.7%", "事件分布有占比（2/3）");
    CHECK_HAS("class=\"col peak\"", "直方图标出峰值");
    CHECK_HAS("203.0.113.7", "Top 源 IP 出现在报告里");
    CHECK_HAS("<td>-</td>", "空字段（进程名）显示为 -");
}

static void TestEscaping(void)
{
    LogEntry logs[1];
    char evil[256];

    CopyStr(evil, sizeof(evil), "<script>alert(\"x\")</script>");
    logs[0] = MakeLog(4624, evil, "2026/10/31-09:12:00", "10.0.0.1");
    CopyStr(logs[0].processName, sizeof(logs[0].processName), "tools\\a&b\\<c>.exe");

    CHECK(Render(logs, 1, "all", "文件 x.evtx") == 1, "转义场景渲染成功");
    CHECK_HAS("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", "尖括号与引号被转义");
    CHECK_NOT_HAS("<script>alert", "没有可执行的 script 标签");
    CHECK_HAS("tools\\a&amp;b\\&lt;c&gt;.exe", "进程名中的 & 与尖括号被转义");
}

static void TestEmpty(void)
{
    CHECK(Render(NULL, 0, "all", "文件 空.evtx") == 1, "空样本也能生成报告");
    CHECK_HAS("没有事件数据。", "空样本提示没有事件");
    CHECK_HAS("没有记录。", "空样本提示没有记录");
    CHECK_HAS("共 <b>0</b> 条记录", "空样本总数为 0");
}

static void TestBadArguments(void)
{
    LogEntry log;
    StatsSummary summary;
    FILE *fp;

    log = MakeLog(4624, "u", "2026/10/31-09:12:00", "1.1.1.1");
    CHECK(Stats_Compute(&log, 1, &summary) == 0, "准备统计结果");

    CHECK(Report_WriteHtml(NULL, NULL, &summary, &log, 1) == -1, "fp=NULL 被拒绝");
    fp = tmpfile();
    CHECK(fp != NULL, "能开临时文件");
    if (fp != NULL) {
        CHECK(Report_WriteHtml(fp, NULL, &summary, &log, 1) == -1, "meta=NULL 被拒绝");
        fclose(fp);
    }
    CHECK(Report_WriteHtml(NULL, NULL, NULL, NULL, 0) == -1, "全 NULL 被拒绝");
}

int main(void)
{
    TestConsoleUtf8();
    TestStructure();
    TestEscaping();
    TestEmpty();
    TestBadArguments();

    printf("\n%d checks, %d failed.\n", g_total, g_failed);
    if (g_failed == 0) {
        printf("All report tests passed!\n");
        return 0;
    }
    return 1;
}
