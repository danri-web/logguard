#ifndef EXPORT_H
#define EXPORT_H

#include "log_entry.h"

/* 将日志数组导出为 CSV 文件，返回成功导出的条数，<0 表示失败 */
int ExportToCsv(const LogEntry *logs, int count, const char *filename);

#endif