#ifndef XML_PARSER_H
#define XML_PARSER_H

#include <stddef.h>
#include "log_entry.h"

/*
 * 把 EvtRender 产出的单条事件 XML 解析为 LogEntry。
 * 只提取本项目关心的字段；缺失字段填空串或 0。
 * 返回：0 成功，-1 解析失败（例如 XML 非法或缺少 EventID）。
 */
int ParseEventXml(const wchar_t *xml, LogEntry *out);

/* ---------- 内部工具，暴露出来便于单元测试 ---------- */

/*
 * 从 XML 中读取 <EventID> 的整数值。
 * 返回：0 成功，-1 未找到。
 */
int XmlGetEventId(const wchar_t *xml, int *eventId);

/*
 * 读取 <Data Name="name">value</Data> 中的 value，
 * 转换为 UTF-8 写入 out（带终止符）。
 * 返回：0 成功，-1 未找到该 Data 节点。
 */
int XmlGetDataValue(const wchar_t *xml, const wchar_t *name,
                    char *out, size_t outLen);

/*
 * 读取 <TimeCreated SystemTime="..."> 并转换为本地时间字符串
 * "YYYY/MM/DD-HH:MM:SS"。
 * 返回：0 成功，-1 失败。
 */
int XmlGetTimeCreated(const wchar_t *xml,
                      char *out, size_t outLen);

#endif /* XML_PARSER_H */