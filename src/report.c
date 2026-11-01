#include <stdio.h>
#include <string.h>

#include "report.h"
#include "stats.h"

/* HTML 转义：日志里的用户名/进程名可能带 < > & " '，一律当文本 */
static void Esc(FILE *fp, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;

    if (s == NULL) return;
    for (; *p != '\0'; p++) {
        switch (*p) {
            case '&': fputs("&amp;", fp); break;
            case '<': fputs("&lt;", fp); break;
            case '>': fputs("&gt;", fp); break;
            case '"': fputs("&quot;", fp); break;
            case '\'': fputs("&#39;", fp); break;
            default:
                /* 控制字符（含换行/制表）进表格前压成空格，避免撑坏排版 */
                if (*p < 0x20) fputc(' ', fp);
                else fputc((int)*p, fp);
                break;
        }
    }
}

static void WriteCss(FILE *fp)
{
    fputs(
        "<style>\n"
        ":root{--fg:#1f2328;--muted:#656d76;--bg:#fff;--panel:#f6f8fa;--line:#d0d7de;"
        "--accent:#0969da;--danger:#cf222e}\n"
        "@media (prefers-color-scheme:dark){:root{--fg:#e6edf3;--muted:#9198a1;--bg:#0d1117;"
        "--panel:#151b23;--line:#3d444d;--accent:#4493f8;--danger:#f85149}}\n"
        "*{box-sizing:border-box}\n"
        "body{margin:0;padding:32px 20px;background:var(--bg);color:var(--fg);"
        "font:15px/1.6 -apple-system,\"Segoe UI\",\"Microsoft YaHei\",sans-serif}\n"
        ".page,main{max-width:1100px;margin:0 auto}\n"
        "h1{font-size:22px;margin:0 0 6px}\n"
        ".sub{color:var(--muted);font-size:13px;margin:0 0 28px;word-break:break-all}\n"
        "h2{font-size:16px;margin:28px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}\n"
        ".summary{color:var(--muted);font-size:13px;margin:0 0 8px}\n"
        ".bar-row{display:grid;grid-template-columns:190px 1fr 130px;gap:10px;"
        "align-items:center;margin:6px 0;font-size:13px}\n"
        ".bar-row .label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n"
        ".bar{background:var(--panel);border-radius:4px;height:14px;overflow:hidden}\n"
        ".bar .fill{display:block;height:100%;background:var(--accent);border-radius:4px}\n"
        ".bar .fill.danger{background:var(--danger)}\n"
        ".num{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums;"
        "white-space:nowrap}\n"
        ".chart{display:flex;align-items:flex-end;gap:4px;height:180px;"
        "padding-top:8px;border-bottom:1px solid var(--line)}\n"
        ".chart .col{flex:1;height:100%;display:flex;flex-direction:column;"
        "justify-content:flex-end;align-items:center}\n"
        ".chart .col i{display:block;width:100%;background:var(--accent);"
        "border-radius:3px 3px 0 0;min-height:0}\n"
        ".chart .col.peak i{background:var(--danger)}\n"
        ".chart .col em{font-style:normal;font-size:10px;color:var(--muted);margin-top:4px}\n"
        ".empty{color:var(--muted)}\n"
        "table{width:100%;border-collapse:collapse;font-size:13px;margin-top:4px}\n"
        "th,td{padding:7px 8px;border-bottom:1px solid var(--line);text-align:left;"
        "vertical-align:top}\n"
        "th{background:var(--panel);font-weight:600;position:sticky;top:0}\n"
        "td.mono{font-family:ui-monospace,Consolas,\"Courier New\",monospace;white-space:nowrap}\n"
        "p.note{color:var(--muted);font-size:12px;margin-top:28px}\n"
        "</style>\n",
        fp);
}

/* 一条横条：宽度按本组最大值缩放，右侧写次数（事件分布额外写占比） */
static void WriteBarRow(FILE *fp, const char *label, int count, int maxCount,
                        int total, int showPct, int danger)
{
    int width = (maxCount > 0) ? (count * 100 + maxCount - 1) / maxCount : 0;

    if (count > 0 && width < 2) width = 2;
    if (width > 100) width = 100;

    fputs("  <div class=\"bar-row\"><span class=\"label\">", fp);
    Esc(fp, label);
    fputs("</span><div class=\"bar\"><span class=\"", fp);
    fputs(danger ? "fill danger" : "fill", fp);
    fprintf(fp, "\" style=\"width:%d%%\"></span></div><span class=\"num\">%d", width, count);
    if (showPct && total > 0) {
        fprintf(fp, " 条 · %.1f%%", (double)count * 100.0 / (double)total);
    } else {
        fputs(" 次", fp);
    }
    fputs("</span></div>\n", fp);
}

static void WriteHourChart(FILE *fp, const StatsSummary *stats, int maxCount)
{
    int h;

    fputs("<div class=\"chart\" role=\"img\" aria-label=\"按小时直方图\">\n", fp);
    for (h = 0; h < STATS_HOURS; h++) {
        int height = (maxCount > 0) ? (stats->hours[h] * 100 + maxCount - 1) / maxCount : 0;

        if (stats->hours[h] > 0 && height < 2) height = 2;
        if (height > 100) height = 100;

        fprintf(fp,
                "  <div class=\"col%s\" title=\"%02d 时：%d 条\">"
                "<i style=\"height:%d%%\"></i><em>%02d</em></div>\n",
                (h == stats->peakHour) ? " peak" : "", h, stats->hours[h], height, h);
    }
    fputs("</div>\n", fp);
}

static void WriteCell(FILE *fp, const char *tag, const char *value)
{
    fprintf(fp, "<%s>", tag);
    Esc(fp, value);
    fprintf(fp, "</%s>", tag);
}

static void WriteTable(FILE *fp, const LogEntry *logs, int count)
{
    int i;

    fputs("<table>\n<thead><tr><th>#</th><th>EventID</th><th>时间</th><th>用户名</th>"
          "<th>登录类型</th><th>描述</th><th>源 IP</th><th>进程名</th></tr></thead>\n"
          "<tbody>\n", fp);

    for (i = 0; i < count; i++) {
        const LogEntry *log = &logs[i];
        char buffer[16];

        fputs("<tr>", fp);
        snprintf(buffer, sizeof(buffer), "%d", i + 1);
        WriteCell(fp, "td", buffer);   /* 序号列不加 mono，右对齐更像个表 */
        snprintf(buffer, sizeof(buffer), "%d", log->eventId);
        WriteCell(fp, "td", buffer);
        WriteCell(fp, "td", log->dateAndTime);
        WriteCell(fp, "td", log->userName[0] ? log->userName : "-");
        snprintf(buffer, sizeof(buffer), "%d", log->logOnType);
        WriteCell(fp, "td", buffer);
        WriteCell(fp, "td", log->description);
        WriteCell(fp, "td", log->sourceIP[0] ? log->sourceIP : "-");
        WriteCell(fp, "td", log->processName[0] ? log->processName : "-");
        fputs("</tr>\n", fp);
    }

    fputs("</tbody>\n</table>\n", fp);
}

int Report_WriteHtml(FILE *fp, const ReportMeta *meta,
                     const StatsSummary *stats,
                     const LogEntry *logs, int count)
{
    int i;
    int maxCount;

    if (fp == NULL || meta == NULL || stats == NULL) return -1;
    if (count < 0 || count > LOG_MAX_COUNT) return -1;
    if (count > 0 && logs == NULL) return -1;

    fputs("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n", fp);
    fputs("<meta charset=\"utf-8\">\n", fp);
    fputs("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n", fp);
    fputs("<title>LogGuard 安全日志分析报告</title>\n", fp);
    WriteCss(fp);
    fputs("</head>\n<body>\n<header class=\"page\">\n", fp);
    fputs("  <h1>LogGuard 安全日志分析报告</h1>\n  <p class=\"sub\">规则：", fp);
    Esc(fp, meta->title ? meta->title : "-");
    fputs(" · 数据源：", fp);
    Esc(fp, meta->source ? meta->source : "-");
    fputs(" · 生成时间：", fp);
    Esc(fp, meta->generatedAt ? meta->generatedAt : "-");
    fputs(" · 工具版本：", fp);
    Esc(fp, meta->version ? meta->version : "-");
    fputs("</p>\n</header>\n<main>\n", fp);

    fprintf(fp, "<p class=\"summary\">共 <b>%d</b> 条记录，%d 种事件 ID，"
                "%d 条可解析时间，%d 条时间无法解析。</p>\n",
            stats->total, stats->eventKindCount, stats->hourKnown, stats->hourUnknown);

    /* ---------------- 事件分布 ---------------- */
    fputs("<h2>事件分布</h2>\n", fp);
    if (stats->eventKindCount == 0) {
        fputs("<p class=\"empty\">没有事件数据。</p>\n", fp);
    } else {
        maxCount = 0;
        for (i = 0; i < stats->eventKindCount; i++) {
            if (stats->events[i].count > maxCount) maxCount = stats->events[i].count;
        }
        for (i = 0; i < stats->eventKindCount; i++) {
            char label[64];

            snprintf(label, sizeof(label), "%d %s",
                     stats->events[i].eventId,
                     Stats_EventName(stats->events[i].eventId));
            WriteBarRow(fp, label, stats->events[i].count, maxCount, stats->total, 1,
                        stats->events[i].eventId == 4625);
        }
        if (stats->otherEventCount > 0) {
            fprintf(fp, "<p class=\"empty\">另有 %d 条记录的 EventID 超出展示上限，未展开。</p>\n",
                    stats->otherEventCount);
        }
    }

    /* ---------------- Top 源 IP ---------------- */
    fputs("<h2>Top 源 IP</h2>\n", fp);
    if (stats->ipCount == 0) {
        fputs("<p class=\"empty\">没有可用源 IP（本机登录或该事件不带 IpAddress）。</p>\n", fp);
    } else {
        maxCount = stats->ips[0].count;
        for (i = 0; i < stats->ipCount; i++) {
            WriteBarRow(fp, stats->ips[i].label, stats->ips[i].count, maxCount,
                        stats->total, 0, 0);
        }
    }

    /* ---------------- Top 用户名 ---------------- */
    fputs("<h2>Top 用户名</h2>\n", fp);
    if (stats->userCount == 0) {
        fputs("<p class=\"empty\">没有可用用户名。</p>\n", fp);
    } else {
        maxCount = stats->users[0].count;
        for (i = 0; i < stats->userCount; i++) {
            WriteBarRow(fp, stats->users[i].label, stats->users[i].count, maxCount,
                        stats->total, 0, 0);
        }
    }

    /* ---------------- 按小时直方图 ---------------- */
    fputs("<h2>按小时直方图</h2>\n", fp);
    if (stats->hourKnown == 0) {
        fputs("<p class=\"empty\">时间字段缺失或无法解析，直方图跳过。</p>\n", fp);
    } else {
        maxCount = 0;
        for (i = 0; i < STATS_HOURS; i++) {
            if (stats->hours[i] > maxCount) maxCount = stats->hours[i];
        }
        WriteHourChart(fp, stats, maxCount);
        if (stats->peakHour >= 0) {
            fprintf(fp, "<p class=\"empty\">峰值时段：%02d 时，%d 条。</p>\n",
                    stats->peakHour, stats->hours[stats->peakHour]);
        }
        if (stats->hourUnknown > 0) {
            fprintf(fp, "<p class=\"empty\">另有 %d 条时间无法解析，未计入直方图。</p>\n",
                    stats->hourUnknown);
        }
    }

    /* ---------------- 记录明细 ---------------- */
    fprintf(fp, "<h2>记录明细（%d 条）</h2>\n", count);
    if (count == 0) {
        fputs("<p class=\"empty\">没有记录。</p>\n", fp);
    } else {
        WriteTable(fp, logs, count);
    }

    fprintf(fp, "<p class=\"note\">本报告由 LogGuard %s 生成，单文件、无外部依赖；"
                "样本最多 1024 条。数据来自 Windows 事件日志，请妥善保管。</p>\n",
            meta->version ? meta->version : "");
    fputs("</main>\n</body>\n</html>\n", fp);

    return ferror(fp) ? -1 : 0;
}
