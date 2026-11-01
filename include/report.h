#ifndef REPORT_H
#define REPORT_H

#include <stdio.h>

#include "log_entry.h"
#include "stats.h"

/* 报告头部的元信息；字符串都按 UTF-8 原样写入 HTML（会转义） */
typedef struct {
    const char *title;        /* 查询规则 / 报告副标题 */
    const char *source;       /* 数据源描述 */
    const char *version;      /* 工具版本 */
    const char *generatedAt;  /* 生成时间（本地时间字符串） */
} ReportMeta;

/*
 * 生成单文件 HTML 报告：内嵌 CSS，四块统计图 + 记录明细表。
 * fp 由调用方打开/关闭；本函数不负责文件编码（按 UTF-8 写出）。
 * 返回 0 成功，-1 参数非法或写入失败（调用方可用 ferror 复核）。
 * 纯 C99，不依赖 Win32，方便单元测试。
 */
int Report_WriteHtml(FILE *fp, const ReportMeta *meta,
                     const StatsSummary *stats,
                     const LogEntry *logs, int count);

#endif /* REPORT_H */
