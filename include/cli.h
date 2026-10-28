#ifndef CLI_H
#define CLI_H

#include <stddef.h>

/* 命令行里的路径上限（宽字符数），比 MAX_PATH 宽裕一些 */
#define CLI_PATH_MAX 512

/*
 * 命令行解析结果。
 * filterId 用菜单编号表示：1=all 2=failed 3=admin 4=brute 5=night 6=privilege 7=created
 * filterId == 0 表示未指定，调用方按默认值处理。
 */
typedef struct {
    int batch;                    /* 1 = 走批处理，不进入交互菜单 */
    int help;
    int version;
    int noColor;

    int hasFile;
    wchar_t file[CLI_PATH_MAX];

    int hasExport;
    wchar_t exportPath[CLI_PATH_MAX];

    int filterId;
    int limit;                    /* 0 = 未指定 */

    const char *error;            /* 解析失败时的静态错误文本（UTF-8）；NULL 表示成功 */
} CliOptions;

void Cli_Init(CliOptions *opt);

/* 解析完整 argv（argv[0] 为程序名）。返回 0 成功，-1 失败（详情看 opt->error）。 */
int Cli_Parse(int argc, wchar_t *const *argv, CliOptions *opt);

/* 把 --filter 的英文名映射成菜单编号；未知返回 0。 */
int Cli_FilterIdFromName(const wchar_t *name);

/* 菜单编号对应的英文名；未知返回 "all"。 */
const char *Cli_FilterName(int filterId);

/* 帮助文本（UTF-8），直接输出到 stdout。 */
void Cli_PrintUsage(void);

#endif /* CLI_H */
