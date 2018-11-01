#ifndef __CT_LIB_H__
#define __CT_LIB_H__

#include <arpa/inet.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#define ct_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/*
 * ct_container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 */
#define ct_container_of(ptr, type, member) ({          \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - ct_offsetof(type,member) );})

#define CT_ARRAY_SIZE(array)    (sizeof(array)/sizeof(array[0]))

extern void str_to_hex(uint8_t *dest, const char *src, int len);

#endif
