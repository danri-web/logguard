#include <stdio.h>
#include "ui.h"

void PrintWelcome(void)
{
    printf("============================================================\n");
    printf("       欢迎使用 LogGuard 终端安全日志分析系统 V2.0\n");
    printf("       数据源：本机 Windows Security 事件日志\n");
    printf("============================================================\n");
}

/* 直接遍历菜单数组打印，再也不用 if (option == 1) 了 */
void PrintMenu(const MenuItem *menu, int menuSize)
{
    printf("\n============================================================\n");
    printf("                       LogGuard v2.0\n");
    printf("============================================================\n");
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