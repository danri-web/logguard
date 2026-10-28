cmake_minimum_required(VERSION 3.10)
project(LogGuard C)

# 统一设置 C 标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# GCC/Clang 下开启严格警告；MSVC 不认 -Wall，跳过
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra)
endif()

# 收集源文件（注意：export.c / cli.c 必须在内）
set(SOURCES
    src/main.c
    src/log_reader.c
    src/xml_parser.c
    src/filter.c
    src/ui.c
    src/export.c
    src/cli.c
)

# Windows 特有的资源文件（manifest 嵌入）
if(WIN32)
    list(APPEND SOURCES app.rc)
endif()

# 主程序
add_executable(LogGuard ${SOURCES})
target_include_directories(LogGuard PRIVATE include)

# 链接 Windows 事件日志 API 库
if(WIN32)
    target_link_libraries(LogGuard PRIVATE wevtapi shell32)
endif()

# ---------------------------------------------------------
# 测试工程（filter/cli 不依赖 Windows API；xml 仅在 Windows 上构建）
# ---------------------------------------------------------
enable_testing()

add_executable(test_filter
    tests/test_filter.c
    src/filter.c
)
target_include_directories(test_filter PRIVATE include)

add_test(NAME TestFilter COMMAND test_filter)

add_executable(test_cli
    tests/test_cli.c
    src/cli.c
)
target_include_directories(test_cli PRIVATE include)

add_test(NAME TestCli COMMAND test_cli)

if(WIN32)
    add_executable(test_xml
        tests/test_xml.c
        src/xml_parser.c
    )
    target_include_directories(test_xml PRIVATE include)

    add_test(NAME TestXml COMMAND test_xml)
endif()
