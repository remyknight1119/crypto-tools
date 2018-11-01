#include <assert.h>
#include <string.h>
#include <ctype.h>

#include "lib.h"

void
str_to_hex(uint8_t *dest, const char *src, int len)
{
    char    h1 = 0;
    char    h2 = 0;
    uint8_t s1 = 0;
    uint8_t s2 = 0;
    int     i = 0;;

    assert(len*2 <= strlen(src));
    for (i = 0; i < len; i++) {
        h1 = src[2*i];
        h2 = src[2*i + 1];

        s1 = toupper(h1) - 0x30;
        if (s1 > 9) {
            s1 -= 7;
        }

        s2 = toupper(h2) - 0x30;
        if (s2 > 9) {
            s2 -= 7;
        }

        dest[i] = s1*16 + s2;
    }
}
