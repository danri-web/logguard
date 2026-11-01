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
 * 四类安全审计事件：4624 登录成功 / 4625 登录失败 / 4672 特权分配 / 4720 创建账户。
 * 只按 EventID 判断，不校验 Provider —— 见 README「已知限制」。
 */
int Filter_SecurityEvent(const LogEntry *log);

/*
 * 判断源 IP 是否可用于聚合统计。
 * 空串和 "-"（Windows 对本机登录/无来源时的占位值）返回 0，其余返回 1。
 */
int Filter_HasSourceIp(const char *ip);

/* 取账户名的本地部分：DOMAIN\admin -> admin；无域前缀时原样返回。 */
const char *Filter_AccountName(const char *name);

/*
 * 从 "YYYY/MM/DD-HH:MM:SS" 中取出小时（0-23）。
 * 时间为空或格式异常时返回 -1，调用方必须把失败和「0 点」区分开。
 */
int Filter_ParseHour(const char *dateAndTime);

#endif