#ifndef FILTER_H
#define FILTER_H

#include "log_entry.h"

typedef int (*FilterFunc)(const LogEntry *log);

int Filter_All(const LogEntry *log);
int Filter_FailedLogin(const LogEntry *log);
int Filter_AdminFailed(const LogEntry *log);
int Filter_BruteForce(const LogEntry *log);
int Filter_NightLogin(const LogEntry *log);
int Filter_Privilege(const LogEntry *log);
int Filter_AccountCreated(const LogEntry *log);

/*
 * 判断源 IP 是否可用于聚合统计。
 * 空串和 "-"（Windows 对本机登录/无来源时的占位值）返回 0，其余返回 1。
 */
int Filter_HasSourceIp(const char *ip);

#endif