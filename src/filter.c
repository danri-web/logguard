#include <string.h>
#include <stdlib.h>
#include "filter.h"

/* 取账户名的本地部分：DOMAIN\admin -> admin；无域前缀时原样返回 */
static const char *AccountNamePart(const char *name)
{
    const char *slash = strrchr(name, '\\');
    return slash ? slash + 1 : name;
}

/* ASCII 大小写无关比较；不依赖 _stricmp，方便跨平台编译单元测试 */
static int EqualsIgnoreCase(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

/*
 * 从 "YYYY/MM/DD-HH:MM:SS" 中取出小时。
 * 解析失败返回 -1 —— 调用方必须把失败和「0 点」区分开，否则会误报。
 */
static int ParseHour(const char *dateAndTime)
{
    if (dateAndTime == NULL || strlen(dateAndTime) < 14) return -1;
    if (dateAndTime[10] != '-' || dateAndTime[13] != ':') return -1;
    if (dateAndTime[11] < '0' || dateAndTime[11] > '9') return -1;
    if (dateAndTime[12] < '0' || dateAndTime[12] > '9') return -1;
    return (dateAndTime[11] - '0') * 10 + (dateAndTime[12] - '0');
}

int Filter_All(const LogEntry *log) { (void)log; return 1; }

int Filter_FailedLogin(const LogEntry *log) {
    return log->eventId == 4625;
}

int Filter_AdminFailed(const LogEntry *log) {
    if (log->eventId != 4625) return 0;
    return EqualsIgnoreCase(AccountNamePart(log->userName), "admin");
}

int Filter_BruteForce(const LogEntry *log) {
    return log->eventId == 4625;
}

/* 新增：凌晨异常登录 */
int Filter_NightLogin(const LogEntry *log) {
    if (log->eventId != 4624) return 0; // 必须是登录成功

    int hour = ParseHour(log->dateAndTime);
    if (hour < 0) return 0; // 时间为空/格式异常：不算凌晨，避免误报

    // 如果是 0 点到 5 点
    return (hour >= 0 && hour < 6);
}

int Filter_Privilege(const LogEntry *log) {
    return log->eventId == 4672;
}

int Filter_AccountCreated(const LogEntry *log) {
    return log->eventId == 4720;
}

/* 聚合统计前判断源 IP 是否可用：空串和 "-" 都不代表真实来源 */
int Filter_HasSourceIp(const char *ip) {
    return ip != NULL && ip[0] != '\0' && strcmp(ip, "-") != 0;
}
