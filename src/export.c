#include <stdio.h>
#include <string.h>
#include "export.h"

/*
 * Excel/WPS 会把以 = + - @ 开头的单元格当作公式执行（CSV 公式注入）。
 * 这类字段一律加 ' 前缀并按文本字段加引号，确保只会被当成普通字符串。
 */
static int StartsWithFormulaChar(const char *str)
{
    if (str[0] == '=' || str[0] == '+' || str[0] == '@') return 1;
    /* 单独的 "-"（Windows 的“无来源 IP”占位符）不是公式，不必加前缀 */
    if (str[0] == '-' && str[1] != '\0') return 1;
    return 0;
}

/* 内部辅助函数：处理带逗号、引号、换行或公式前缀的字符串转义 */
static void WriteCsvField(FILE *fp, const char *str)
{
    int hasSpecial = StartsWithFormulaChar(str) ? 1 : 0;

    if (strchr(str, ',') || strchr(str, '"') ||
        strchr(str, '\n') || strchr(str, '\r')) {
        hasSpecial = 1;
    }

    if (hasSpecial) {
        fputc('"', fp);
        if (StartsWithFormulaChar(str)) fputc('\'', fp); /* 公式注入防护 */
        for (int i = 0; str[i] != '\0'; i++) {
            if (str[i] == '"') fputc('"', fp); // 双引号转义为两个双引号
            fputc(str[i], fp);
        }
        fputc('"', fp);
    } else {
        fputs(str, fp);
    }
}

int ExportToCsv(const LogEntry *logs, int count, const char *filename)
{
    if (!logs || count <= 0 || !filename) return -1;

    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;

    /* 写入 UTF-8 BOM 头，防止 Excel 打开中文乱码 */
    fprintf(fp, "\xEF\xBB\xBF");

    /* 写入表头 */
    fprintf(fp, "序号,EventID,时间,用户名,登录类型,描述,源IP,进程名\n");

    /* 写入数据 */
    for (int i = 0; i < count; i++) {
        fprintf(fp, "%d,", i + 1);
        fprintf(fp, "%d,", logs[i].eventId);
        WriteCsvField(fp, logs[i].dateAndTime); fprintf(fp, ",");
        WriteCsvField(fp, logs[i].userName);   fprintf(fp, ",");
        fprintf(fp, "%d,", logs[i].logOnType);
        WriteCsvField(fp, logs[i].description);fprintf(fp, ",");
        WriteCsvField(fp, logs[i].sourceIP);   fprintf(fp, ",");
        WriteCsvField(fp, logs[i].processName);fprintf(fp, "\n");
    }

    /* 写完必须检查错误，否则磁盘满/权限问题会被当成“导出成功” */
    if (ferror(fp)) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0) return -1;

    return count;
}
