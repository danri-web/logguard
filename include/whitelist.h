#ifndef WHITELIST_H
#define WHITELIST_H

#include "log_entry.h"

#define WHITELIST_MAX_RULES 64
#define WHITELIST_VALUE_LEN 128

/*
 * 白名单：把「已知的、不值得报的」账户和源 IP 从样本里剔掉。
 * 典型用法是服务账号（SYSTEM / 机器账号）和扫描器/监控机的固定 IP。
 *
 * 文件格式（UTF-8 纯文本，一行一条）：
 *   # 井号开头是注释
 *   ip   10.0.0.5        精确匹配源 IP
 *   user svc_backup      匹配账户名（会去掉 DOMAIN\ 前缀，大小写无关）
 * 认不出来的行会被跳过并计数，不会让整个查询失败。
 */

typedef struct {
    int  isIp;                        /* 1 = ip，0 = user */
    char value[WHITELIST_VALUE_LEN];
} WhitelistRule;

typedef struct {
    WhitelistRule rules[WHITELIST_MAX_RULES];
    int count;
    int skipped;                      /* 无法识别的行数 */
} Whitelist;

void Whitelist_Init(Whitelist *wl);

/*
 * 读取白名单文件。路径按宽字符传，文件可以是中文路径。
 * 返回：0 成功（文件存在且已读完），-1 打不开文件。
 */
int Whitelist_Load(Whitelist *wl, const wchar_t *path);

/*
 * 解析一行（暴露出来给单元测试，不碰文件）。
 * 返回：1 新增一条规则，0 空行/注释，-1 认不出或规则已满。
 */
int Whitelist_ParseLine(Whitelist *wl, const char *line);

/* 命中任意一条规则返回 1（该条记录应被忽略） */
int Whitelist_Match(const Whitelist *wl, const LogEntry *log);

/*
 * 原地剔除命中白名单的记录，返回剔除条数。
 * 没配白名单时直接返回 0，不动数组。
 */
int Whitelist_Filter(LogEntry *logs, int count, const Whitelist *wl);

#endif /* WHITELIST_H */
