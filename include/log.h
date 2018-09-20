#ifndef __CT_LOG_H__
#define __CT_LOG_H__

#include <stdio.h>

#define CT_LOG(format, ...) \
    do { \
        fprintf(stdout, "[%u][%s, %d]: "format, packet_count,  __FUNCTION__, \
                __LINE__, ##__VA_ARGS__); \
    } while (0)

extern int packet_count;

#endif
