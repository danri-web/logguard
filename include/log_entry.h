#ifndef LOG_ENTRY_H
#define LOG_ENTRY_H

#define LOG_MAX_COUNT 1024

#define LOG_TIME_LEN     32
#define LOG_USER_LEN    256
#define LOG_DESC_LEN    256
#define LOG_IP_LEN       64
#define LOG_PROC_LEN    128

typedef struct {
    int  eventId;                          
    char dateAndTime[LOG_TIME_LEN];        
    char userName[LOG_USER_LEN];           
    int  logOnType;                        
    char description[LOG_DESC_LEN];        
    char sourceIP[LOG_IP_LEN];             
    char processName[LOG_PROC_LEN];        
} LogEntry;

#endif