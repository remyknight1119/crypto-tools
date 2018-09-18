#ifndef __TOOL_H__
#define __TOOL_H__


extern int ct_decrypt_file(const char *output, const char *input,
                const char *key, const char *random,
                const char *filter_str);

#endif
