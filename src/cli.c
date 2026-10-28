#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "cli.h"
#include "log_entry.h"
#include "version.h"

typedef struct {
    const wchar_t *name;
    const char *ascii;
    int id;
} FilterName;

static const FilterName kFilterNames[] = {
    {L"all",       "all",       1},
    {L"failed",    "failed",    2},
    {L"admin",     "admin",     3},
    {L"brute",     "brute",     4},
    {L"night",     "night",     5},
    {L"privilege", "privilege", 6},
    {L"created",   "created",   7}
};

static int WcsEqual(const wchar_t *a, const wchar_t *b)
{
    return wcscmp(a, b) == 0;
}

/* 只处理 ASCII 的大小写折叠，参数名和过滤器名都是 ASCII */
static int WcsEqualNoCase(const wchar_t *a, const wchar_t *b)
{
    while (*a != L'\0' && *b != L'\0') {
        wchar_t ca = *a;
        wchar_t cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca = (wchar_t)(ca - L'A' + L'a');
        if (cb >= L'A' && cb <= L'Z') cb = (wchar_t)(cb - L'A' + L'a');
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == L'\0' && *b == L'\0';
}

static int CopyPath(wchar_t *dst, const wchar_t *src)
{
    size_t n = wcslen(src);
    if (n == 0 || n >= CLI_PATH_MAX) return 0;
    memcpy(dst, src, (n + 1) * sizeof(wchar_t));
    return 1;
}

static int Fail(CliOptions *opt, const char *msg)
{
    opt->error = msg;
    return -1;
}

static int ParseLimit(const wchar_t *s, int *out)
{
    wchar_t *end = NULL;
    long value;

    if (s == NULL || *s == L'\0') return 0;
    value = wcstol(s, &end, 10);
    if (end == s || *end != L'\0') return 0;
    if (value < 1 || value > LOG_MAX_COUNT) return 0;

    *out = (int)value;
    return 1;
}

void Cli_Init(CliOptions *opt)
{
    if (!opt) return;
    memset(opt, 0, sizeof(*opt));
}

int Cli_FilterIdFromName(const wchar_t *name)
{
    size_t i;
    if (!name) return 0;
    for (i = 0; i < sizeof(kFilterNames) / sizeof(kFilterNames[0]); i++) {
        if (WcsEqualNoCase(name, kFilterNames[i].name)) return kFilterNames[i].id;
    }
    return 0;
}

const char *Cli_FilterName(int filterId)
{
    size_t i;
    for (i = 0; i < sizeof(kFilterNames) / sizeof(kFilterNames[0]); i++) {
        if (kFilterNames[i].id == filterId) return kFilterNames[i].ascii;
    }
    return "all";
}

int Cli_Parse(int argc, wchar_t *const *argv, CliOptions *opt)
{
    int i;

    Cli_Init(opt);
    if (!opt || !argv || argc <= 0) return -1;

    for (i = 1; i < argc; i++) {
        const wchar_t *arg = argv[i];

        if (WcsEqual(arg, L"--help") || WcsEqual(arg, L"-h")) {
            opt->help = 1;
        } else if (WcsEqual(arg, L"--version") || WcsEqual(arg, L"-V")) {
            opt->version = 1;
        } else if (WcsEqual(arg, L"--no-color")) {
            opt->noColor = 1;
        } else if (WcsEqual(arg, L"--file")) {
            if (++i >= argc) return Fail(opt, "--file 需要一个 .evtx 文件路径");
            if (!CopyPath(opt->file, argv[i])) {
                return Fail(opt, "--file 路径为空或过长（最多 511 个字符）");
            }
            opt->hasFile = 1;
            opt->batch = 1;
        } else if (WcsEqual(arg, L"--filter")) {
            const wchar_t *value;
            if (++i >= argc) {
                return Fail(opt, "--filter 需要 all/failed/admin/brute/night/privilege/created 或 1-7");
            }
            value = argv[i];
            if (value[0] >= L'1' && value[0] <= L'7' && value[1] == L'\0') {
                opt->filterId = (int)(value[0] - L'0');
            } else {
                opt->filterId = Cli_FilterIdFromName(value);
                if (opt->filterId == 0) {
                    return Fail(opt, "未知的 --filter 值（可用 all/failed/admin/brute/night/privilege/created 或 1-7）");
                }
            }
            opt->batch = 1;
        } else if (WcsEqual(arg, L"--limit")) {
            if (++i >= argc) return Fail(opt, "--limit 需要一个 1-1024 之间的数字");
            if (!ParseLimit(argv[i], &opt->limit)) {
                return Fail(opt, "--limit 超出范围（1-1024）");
            }
            opt->batch = 1;
        } else if (WcsEqual(arg, L"--export")) {
            if (++i >= argc) return Fail(opt, "--export 需要一个 CSV 文件路径");
            if (!CopyPath(opt->exportPath, argv[i])) {
                return Fail(opt, "--export 路径为空或过长（最多 511 个字符）");
            }
            opt->hasExport = 1;
            opt->batch = 1;
        } else if (arg[0] == L'-') {
            return Fail(opt, "未知参数（用 --help 查看用法）");
        } else {
            return Fail(opt, "不接受位置参数（用 --file 指定日志文件）");
        }
    }

    return 0;
}

void Cli_PrintUsage(void)
{
    printf("%s %s - Windows 安全日志分析\n\n", LOGUARD_NAME, LOGUARD_VERSION);
    printf("用法：\n");
    printf("  LogGuard.exe                    进入交互菜单（默认数据源为本机 Security）\n");
    printf("  LogGuard.exe [选项]             批处理模式，执行完直接退出\n\n");
    printf("选项：\n");
    printf("  --file <路径>      分析 .evtx 文件（不指定则读本机 Security 通道）\n");
    printf("  --filter <规则>    all | failed | admin | brute | night | privilege | created\n");
    printf("                     也可以直接写菜单编号 1-7\n");
    printf("  --limit <条数>      最多读取多少条，1-1024（默认按规则）\n");
    printf("  --export <路径>     把结果导出为 CSV 文件\n");
    printf("  --no-color          关闭 ANSI 颜色\n");
    printf("  -h, --help          显示本帮助\n");
    printf("  -V, --version       显示版本号\n\n");
    printf("示例：\n");
    printf("  LogGuard.exe --file logs\\Security.evtx --filter failed --limit 200\n");
    printf("  LogGuard.exe --file Security.evtx --filter brute --export report.csv\n");
    printf("  LogGuard.exe --file Security.evtx --filter 6 --no-color\n");
}
