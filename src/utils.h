#ifndef _UTILS_H_
#define _UTILS_H_
#include <stdint.h>
#include <stdio.h>

#include "error.h"

#define M_QUOTE(name) #name
#define M_STR(macro)  M_QUOTE(macro)

#define MAXLEN_ALGONAME (128)
#define KEY_SIZE (256)

#ifndef _PREFIX
#   define PREFIX "privacy"
#else
#   define PREFIX M_STR(_PREFIX)
#endif

#ifndef NO_DEBUG
#  define dbglog(...) do { \
    FILE * __l = fopen("/tmp/ppdbg.log", "a+"); \
    if (!__l) break; \
	char tmp[1024]; \
    fprintf(__l, "[%s][%-15s:%4d]: ", timestamp(tmp), __FILE__, __LINE__); \
    fprintf(__l, __VA_ARGS__); \
    fclose(__l); \
} while (0)

#  define loghex( p, len) do { \
    char __bytes[2048]; \
    int __i = 0; \
    for (__i = 0; __i < (len); __i++) { \
        __bytes[__i * 2 + 0] = "0123456789abcdef"[(int)p[__i] / 16]; \
        __bytes[__i * 2 + 1] = "0123456789abcdef"[(int)p[__i] % 16]; \
    } \
    __bytes[__i * 2] = 0; \
    dbglog("cypher[%s] len[%d]\n", __bytes, len); \
} while(0)

#else
#  define dbglog(...)
#  define loghex(tag, len)
#endif

/* beg 2014.04.23 zhenxie insert log to db */
#define INSERT_DB_LOG(tag)\
	ret = insert_log_db( tag );\
	if( ret != 0 ){\
		die( ret );\
	}
/* end 2014.04.23 zhenxie insert log to db */

size_t base64_decode(uint8_t * out, const char * in);
size_t base64_encode(char * out, const uint8_t * in, size_t len);

char * timestamp(char *);
size_t compress_numstring(const char *, uint8_t *);
char * flatten_numstring(const uint8_t *, char *);

int get_dbconfig(char *, char *, char *, char *);
char * get_line(FILE *, char *, int);

uint8_t first_salt(const uint8_t *);
uint8_t next_salt(uint8_t);

int check_file_md5(const char *, const char *);

/* beg 2014.04.23 zhenxie insert log to db */
int insert_log_db( const char * );
/* end 2014.04.23 zhenxie insert log to db */

void get_day( char * day  );
#endif
