#ifndef TEST_CONSOLE_UTF8_H
#define TEST_CONSOLE_UTF8_H

/*
 * 测试程序输出 UTF-8 中文，但 Windows 控制台默认是 cp936（GBK），
 * 会把 UTF-8 字节按 GBK 解码，显示成乱码。
 *
 * 这里在 Windows 上把控制台输入/输出代码页切到 65001（UTF-8）；
 * 其他平台是空操作，测试仍然只用标准 C。
 *
 * 注意：只对「直接在当前控制台运行」有效。如果用管道/重定向再交给别的程序
 * 解码，需要在 PowerShell 里设置 [Console]::OutputEncoding。
 */
#ifdef _WIN32
#include <windows.h>

static void TestConsoleUtf8(void)
{
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);
}
#else
static void TestConsoleUtf8(void)
{
}
#endif

#endif /* TEST_CONSOLE_UTF8_H */
