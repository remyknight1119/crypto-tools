#ifndef __CT_LOG_H__
#define __CT_LOG_H__

#include <stdio.h>

#define CT_LOG(format, ...) \
    do { \
        fprintf(stdout, "[%u][%s, %d]: "format, packet_count,  __FUNCTION__, \
                __LINE__, ##__VA_ARGS__); \
    } while (0)

#define CT_PRINT(data, len) \
    do { \
		unsigned char *d = (unsigned char *)data; \
		int i = 0; \
		for (i = 0; i < len; i++) { \
			fprintf(stdout, "%02x ", d[i]); \
		} \
		CT_LOG("\nlen = %d\n", len); \
    } while (0)


extern int packet_count;

#endif
