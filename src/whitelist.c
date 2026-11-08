#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "whitelist.h"
#include "filter.h"

/* ASCII 大小写无关比较；和 filter.c 同一套规则，避免链到 _stricmp */
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

static int IsSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* 去掉首尾空白，返回新的起点；长度写回 *len */
static char *Trim(char *s, size_t *len)
{
    size_t n;

    while (*s != '\0' && IsSpace(*s)) s++;
    n = strlen(s);
    while (n > 0 && IsSpace(s[n - 1])) n--;
    s[n] = '\0';
    if (len != NULL) *len = n;
    return s;
}

void Whitelist_Init(Whitelist *wl)
{
    if (wl == NULL) return;
    memset(wl, 0, sizeof(*wl));
}

int Whitelist_ParseLine(Whitelist *wl, const char *line)
{
    char buffer[512];
    char *p;
    char *kind;
    char *value;
    size_t len = 0;

    if (wl == NULL || line == NULL) return -1;

    /* 复制一份再改：调用方传进来的可能是常量串 */
    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    p = Trim(buffer, &len);
    if (len == 0) return 0;
    if (p[0] == '#' || p[0] == ';') return 0;

    kind = p;
    while (*p != '\0' && !IsSpace(*p)) p++;
    if (*p == '\0') return -1;
    *p = '\0';
    value = Trim(p + 1, &len);
    if (len == 0) return -1;
    if (len >= WHITELIST_VALUE_LEN) return -1;
    if (wl->count >= WHITELIST_MAX_RULES) return -1;

    if (EqualsIgnoreCase(kind, "ip")) {
        wl->rules[wl->count].isIp = 1;
    } else if (EqualsIgnoreCase(kind, "user")) {
        wl->rules[wl->count].isIp = 0;
    } else {
        return -1;
    }

    memcpy(wl->rules[wl->count].value, value, len + 1);
    wl->count++;
    return 1;
}

int Whitelist_Load(Whitelist *wl, const wchar_t *path)
{
    FILE *fp;
    char line[512];
    int first = 1;

    if (wl == NULL || path == NULL) return -1;

    fp = _wfopen(path, L"rb");
    if (fp == NULL) return -1;

    while (fgets(line, sizeof(line), fp) != NULL) {
        const char *text = line;

        /* UTF-8 BOM：记事本另存的文件常带，不去掉会把第一条规则读坏 */
        if (first && (unsigned char)text[0] == 0xEF &&
            (unsigned char)text[1] == 0xBB && (unsigned char)text[2] == 0xBF) {
            text += 3;
        }
        first = 0;

        if (Whitelist_ParseLine(wl, text) < 0) wl->skipped++;
    }

    fclose(fp);
    return 0;
}

int Whitelist_Match(const Whitelist *wl, const LogEntry *log)
{
    int i;

    if (wl == NULL || log == NULL) return 0;

    for (i = 0; i < wl->count; i++) {
        const WhitelistRule *rule = &wl->rules[i];

        if (rule->isIp) {
            /* "-" 是 Windows 的「没有来源」占位值，不该被任何规则匹配 */
            if (!Filter_HasSourceIp(log->sourceIP)) continue;
            if (EqualsIgnoreCase(rule->value, log->sourceIP)) return 1;
        } else {
            if (EqualsIgnoreCase(rule->value, log->userName)) return 1;
            if (EqualsIgnoreCase(rule->value, Filter_AccountName(log->userName))) return 1;
        }
    }
    return 0;
}

int Whitelist_Filter(LogEntry *logs, int count, const Whitelist *wl)
{
    int i;
    int kept = 0;

    if (logs == NULL || count <= 0 || wl == NULL || wl->count == 0) return 0;

    for (i = 0; i < count; i++) {
        if (Whitelist_Match(wl, &logs[i])) continue;
        if (kept != i) logs[kept] = logs[i];
        kept++;
    }
    return count - kept;
}
