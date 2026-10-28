#ifndef UI_H
#define UI_H

#include <stddef.h>
#include "log_entry.h"

/* 声明 MenuItem 结构体 (供 main.c 和 ui.c 共用) */
typedef struct {
    int id;
    const char *name;
    const char *desc;
    int maxRead;
    int isAggregate; /* 是否聚合查询 (比如爆破检测) */
} MenuItem;

/* 修改参数，直接传入 MenuItem；sourceDesc 显示当前数据源 */
void PrintMenu(const MenuItem *menu, int menuSize, const char *sourceDesc);
void PrintHeader(const MenuItem *item);
void PrintFooter(const MenuItem *item, int count);
void PrintLogEntry(const LogEntry *log, int index);
void PrintWelcome(void);
int ReadOption(int *option);
void PrintInfo(const char *msg);
void PrintError(const char *msg);

#endif