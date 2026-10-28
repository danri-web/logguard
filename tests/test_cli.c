#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "cli.h"
#include "log_entry.h"

static int g_total = 0;
static int g_failed = 0;

#define CHECK(cond, msg) \
    do { \
        g_total++; \
        if (!(cond)) { \
            g_failed++; \
            printf("[FAIL] %s (line %d)\n", (msg), __LINE__); \
        } else { \
            printf("[PASS] %s\n", (msg)); \
        } \
    } while (0)

#define CHECK_WSTR(expected, actual, msg) \
    do { \
        g_total++; \
        if (wcscmp((expected), (actual)) != 0) { \
            g_failed++; \
            printf("[FAIL] %s (expected \"%ls\", actual \"%ls\")\n", \
                   (msg), (expected), (actual)); \
        } else { \
            printf("[PASS] %s\n", (msg)); \
        } \
    } while (0)

static void TestHelpAndVersion(void)
{
    CliOptions opt;

    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--help" };
        CHECK(Cli_Parse(2, argv, &opt) == 0, "解析 --help 成功");
        CHECK(opt.help == 1, "--help 置位");
        CHECK(opt.batch == 0, "--help 不进入批处理");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"-h" };
        CHECK(Cli_Parse(2, argv, &opt) == 0 && opt.help == 1, "解析 -h 成功");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--version" };
        CHECK(Cli_Parse(2, argv, &opt) == 0, "解析 --version 成功");
        CHECK(opt.version == 1, "--version 置位");
        CHECK(opt.batch == 0, "--version 不进入批处理");
    }
}

static void TestFileAndExport(void)
{
    CliOptions opt;

    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--file", L"sample.evtx" };
        CHECK(Cli_Parse(3, argv, &opt) == 0, "解析 --file 成功");
        CHECK(opt.hasFile == 1, "--file 置位");
        CHECK_WSTR(L"sample.evtx", opt.file, "--file 路径正确");
        CHECK(opt.batch == 1, "--file 进入批处理");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--export", L"out.csv" };
        CHECK(Cli_Parse(3, argv, &opt) == 0, "解析 --export 成功");
        CHECK(opt.hasExport == 1, "--export 置位");
        CHECK_WSTR(L"out.csv", opt.exportPath, "--export 路径正确");
        CHECK(opt.batch == 1, "--export 进入批处理");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--file", L"a.evtx",
                            L"--filter", L"failed", L"--limit", L"200",
                            L"--export", L"r.csv", L"--no-color" };
        CHECK(Cli_Parse(10, argv, &opt) == 0, "解析完整参数组合成功");
        CHECK(opt.hasFile == 1 && opt.hasExport == 1, "文件与导出同时置位");
        CHECK(opt.filterId == 2, "完整组合中的 filterId 正确");
        CHECK(opt.limit == 200, "完整组合中的 limit 正确");
        CHECK(opt.noColor == 1, "完整组合中的 no-color 正确");
        CHECK(opt.batch == 1, "完整组合进入批处理");
    }
}

static void TestFilters(void)
{
    CliOptions opt;

    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--filter", L"failed" };
        CHECK(Cli_Parse(3, argv, &opt) == 0 && opt.filterId == 2, "--filter failed -> 2");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--filter", L"FAILED" };
        CHECK(Cli_Parse(3, argv, &opt) == 0 && opt.filterId == 2, "--filter 大小写不敏感");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--filter", L"brute" };
        CHECK(Cli_Parse(3, argv, &opt) == 0 && opt.filterId == 4, "--filter brute -> 4");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--filter", L"7" };
        CHECK(Cli_Parse(3, argv, &opt) == 0 && opt.filterId == 7, "--filter 7 -> 7");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--filter", L"nope" };
        CHECK(Cli_Parse(3, argv, &opt) == -1, "--filter 未知值报错");
        CHECK(opt.error != NULL, "--filter 未知值有错误文本");
    }
}

static void TestLimit(void)
{
    CliOptions opt;

    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--limit", L"1" };
        CHECK(Cli_Parse(3, argv, &opt) == 0 && opt.limit == 1, "--limit 1 合法");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--limit", L"1024" };
        CHECK(Cli_Parse(3, argv, &opt) == 0 && opt.limit == LOG_MAX_COUNT, "--limit 上限合法");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--limit", L"0" };
        CHECK(Cli_Parse(3, argv, &opt) == -1, "--limit 0 报错");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--limit", L"1025" };
        CHECK(Cli_Parse(3, argv, &opt) == -1, "--limit 超过上限报错");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--limit", L"abc" };
        CHECK(Cli_Parse(3, argv, &opt) == -1, "--limit 非数字报错");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--limit", L"12x" };
        CHECK(Cli_Parse(3, argv, &opt) == -1, "--limit 尾随字符报错");
    }
}

static void TestErrors(void)
{
    CliOptions opt;

    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--file" };
        CHECK(Cli_Parse(2, argv, &opt) == -1, "--file 缺值报错");
        CHECK(opt.error != NULL, "--file 缺值有错误文本");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--export" };
        CHECK(Cli_Parse(2, argv, &opt) == -1, "--export 缺值报错");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--unknown" };
        CHECK(Cli_Parse(2, argv, &opt) == -1, "未知选项报错");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"sample.evtx" };
        CHECK(Cli_Parse(2, argv, &opt) == -1, "位置参数报错");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--file", L"" };
        CHECK(Cli_Parse(3, argv, &opt) == -1, "--file 空路径报错");
    }
    {
        wchar_t longPath[CLI_PATH_MAX + 1];
        wchar_t *argv[] = { L"LogGuard.exe", L"--file", longPath };
        int i;
        for (i = 0; i < CLI_PATH_MAX; i++) longPath[i] = L'a';
        longPath[CLI_PATH_MAX] = L'\0';
        CHECK(Cli_Parse(3, argv, &opt) == -1, "--file 过长路径报错");
    }
}

static void TestDefaults(void)
{
    CliOptions opt;

    {
        wchar_t *argv[] = { L"LogGuard.exe" };
        CHECK(Cli_Parse(1, argv, &opt) == 0, "无参数解析成功");
        CHECK(opt.batch == 0, "无参数进入交互模式");
        CHECK(opt.filterId == 0 && opt.limit == 0, "无参数时 filter/limit 未指定");
    }
    {
        wchar_t *argv[] = { L"LogGuard.exe", L"--no-color" };
        CHECK(Cli_Parse(2, argv, &opt) == 0, "--no-color 解析成功");
        CHECK(opt.noColor == 1 && opt.batch == 0, "--no-color 单独使用仍是交互模式");
    }
}

int main(void)
{
    TestHelpAndVersion();
    TestFileAndExport();
    TestFilters();
    TestLimit();
    TestErrors();
    TestDefaults();

    printf("\n%d checks, %d failed.\n", g_total, g_failed);
    if (g_failed == 0) {
        printf("All CLI tests passed!\n");
        return 0;
    }
    return 1;
}
