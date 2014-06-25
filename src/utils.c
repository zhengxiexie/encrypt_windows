#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <time.h>

#include "utils.h"
#include "error.h"

#ifndef _PREFIX
#   define PREFIX "privacy"
#else
#   define PREFIX M_STR(_PREFIX)
#endif

size_t base64_decode(uint8_t * out, const char * in) {
    // basic char map for base64 decoding
    static const uint8_t charmap[] = {
/*       0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F */
/* 0 */ 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
/* 1 */ 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
/* 2 */ 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
/* 3 */ 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64,  0, 64, 64,
/* 4 */ 64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
/* 5 */ 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
/* 6 */ 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
/* 7 */ 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    };

    uint32_t quad = 0;
    uint32_t d0 = 0, d1 = 0, d2 = 0, d3 = 0;
    int pi = 0, po = 0, eq_count = 0;
    while (in[pi]) {
        d0 = charmap[(uint8_t)in[pi++]];
        d1 = charmap[(uint8_t)in[pi++]];
        if (in[pi] == '=') eq_count++;
        d2 = charmap[(uint8_t)in[pi++]];
        if (in[pi] == '=') eq_count++;
        d3 = charmap[(uint8_t)in[pi++]];
        quad = 0x00ffffff & ((d0 << 18) | (d1 << 12) | (d2 << 6) | (d3 << 0));
        out[po++] = (uint8_t)((quad >> 16) & 0xff);
        if (eq_count == 2) break;
        out[po++] = (uint8_t)((quad >>  8) & 0xff);
        if (eq_count == 1) break;
        out[po++] = (uint8_t)((quad >>  0) & 0xff);
    }
    return po;
}

size_t base64_encode(char * out, const uint8_t * in, size_t len) {
    static const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    static const char padding = '=';
    static const uint8_t npad[] = {0, 2, 1};
    int po = 0, pi = 0;
    uint32_t triple = 0, d0 = 0, d1 = 0, d2 = 0;
    for (pi = 0; pi < len;) {
        d0 = (pi < len)? (uint8_t)in[pi++]: 0;
        d1 = (pi < len)? (uint8_t)in[pi++]: 0;
        d2 = (pi < len)? (uint8_t)in[pi++]: 0;
        triple = ((d0 << 16) | (d1 << 8) | (d2)) & 0x00ffffff;
        out[po++] = charset[triple >> 18 & 0x3f];
        out[po++] = charset[triple >> 12 & 0x3f];
        out[po++] = charset[triple >> 6  & 0x3f];
        out[po++] = charset[triple >> 0  & 0x3f];
    }

    for (pi = 0; pi < npad[len % 3]; pi++) out[po - pi - 1] = padding;
    out[po] = 0;
    return po;
}

char * timestamp(char * buf) {
    time_t t = time(NULL);
    strftime(buf, 20, "%Y-%m-%d %H:%M:%S", localtime(&t));
    return buf;
}

size_t compress_numstring(const char * in, uint8_t * out) {
    int pi = 0;
#define D(x) ((uint8_t)((x >= '0' && x <= '9')? (x - '0'): \
             ((x == '-')? 0x0A: \
             ((x == '+')? 0x0B: \
             ((x == ' ')? 0x0C: 0xfe)))) + 1)

    for (pi = 0; in[pi]; pi++) {
        uint8_t part = D(in[pi]);
        if (part > 0x0f) return ERROR_NONNUM;
        switch (pi % 2) {
            case 0:
                out[pi / 2]  = (part << 4) & 0xf0;
                break;
            case 1:
                out[pi / 2] |= (part) & 0x0f;
                break;
        }
    }
#undef D
    out[(pi + 1) / 2] = '\0';
    return 0;
}

char * flatten_numstring(const uint8_t * in, char * out) {
    int pi = 0, po = 0;
    static const char chars[] = {
        0,   '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', '-', '+', ' ', 0 };
#define D(x) ((char)(chars[((x)) & 0x0f]))
    for (pi = po = 0; in[pi]; pi++ ) {
        out[po++] = D(in[pi] >> 4);
        out[po++] = D(in[pi]);
    }
#undef D
    out[po] = 0;
    return out;
}

// get dbconfig from file
int get_dbconfig(char * database, char * username, char * password, char * schema) {
    FILE * cfg_file;
    char word[2][256];
    char line[1024];
    int flag_indq = 1;
    int idx_w     = 0;
    int pos_w     = 0;
    int pos       = 0;

	sprintf(line, "%s/%s/privacyprot.cfg", getenv("HOME"), PREFIX); // linux
    /*sprintf(line, "%s/%s/privacyprot.cfg", getenv("HOME")==NULL?"C:":getenv("HOME"), PREFIX); // windows*/
	
    cfg_file = fopen(line, "r");

    if (!cfg_file) return ERROR_CFGFILE;

    while (get_line(cfg_file, line, 1024) != NULL) {
        if (line[0] == '#' || line[0] == 0) continue;
        word[0][0] = '\0';
        word[1][0] = '\0';

        // get word[0] and word[1]
        pos   = 0;
        idx_w = 0;
        pos_w = 0;
        flag_indq = 0;
        memset(word[0], 0, 256);
        memset(word[1], 0, 256);
        while ((idx_w < 2) && (line[pos])) {
            if (line[pos] == '\"') {
                flag_indq = 1 - flag_indq;
                pos++;
            }
            if (line[pos] == '\t' || line[pos] == ' ') {
                if (flag_indq) {
                    word[idx_w][pos_w++] = line[pos];
                    pos++;
                } else {
                    word[idx_w++][pos_w + 1] = 0;
                    pos_w = 0;
                    while (line[pos] == '\t' || line[pos] == ' ') if (line[pos]) pos++;
                }
            } else {
                word[idx_w][pos_w++] = line[pos];
                pos++;
            }
        }

#define _GET_STR_CFG(x) if (0 == strcasecmp(word[0], #x)) { \
    strcpy(x, word[1]); \
    continue; \
}
        _GET_STR_CFG(database);
        _GET_STR_CFG(username);
        _GET_STR_CFG(password);
        _GET_STR_CFG(schema);
#undef _GET_STR_CFG
    }
    fclose(cfg_file);
    return 0;
}

char * get_line(FILE * f, char * line, int len) {
    char * ret = fgets(line, len, f);
    int i = 0;
    if (!ret) {
        line[0] = 0;
        return NULL;
    }

    // trim any EOL
    for (i = strlen(ret) - 1; i >= 0; i--) {
        if (ret[i] == '\r' || ret[i] == '\n') ret[i] = 0;
        else break;
    }
    return ret;
}

// function to generate salt
#define SOME_MAGIC_PRIME_1 (17)
#define SOME_MAGIC_PRIME_2 (31)
uint8_t first_salt(const uint8_t * k) {
    uint8_t ret = 0;
    int t = 0;
    for (t = 0; k[t] && t < KEY_SIZE; t++)
        ret = ret * SOME_MAGIC_PRIME_1 + k[t];
    return ret % 255;
}

uint8_t next_salt(uint8_t s) {
    return (s * SOME_MAGIC_PRIME_2 + SOME_MAGIC_PRIME_1) % 255;
}

int check_file_md5(const char * file, const char * md5) {
    // check MD5 checksum
    char clibuf[128];
    sprintf(clibuf, "md5sum %s", file);
    FILE * p = popen(clibuf, "r");
    get_line(p, clibuf, 64);
    pclose(p);
    return strncasecmp(clibuf, md5, 32);
}

char * decode_hex(char * raw, const char * hex) {
#define D(x) ((x >= '0' && x <= '9')? (x - '0'): \
             ((x >= 'a' && x <= 'f')? (x - 'a' + 10): \
             ((x >= 'A' && x <= 'F')? (x - 'A' + 10): 0)))
    // HEX to raw
    int i = 0;
    for (i = 0; raw[i]; i += 2) {
        uint8_t rh = D(hex[i]);
        uint8_t rl = D(hex[i + 1]);
        raw[i / 2] = (uint8_t)0xff & (rh << 4 | rl);
    }
#undef D
    raw[i / 2] = 0;
    return raw;
}

/* beg 2014.04.23 zhenxie insert log to db */
int insert_log_db( const char * db_log )
{
	int ret = 0;
	char buf[1024];
	snprintf(buf, 1024, "%s/" PREFIX "/pputil log %s", getenv("HOME"), db_log); // linux
	/*snprintf(buf, 1024, "%s/" PREFIX "/pputil log %s", getenv("HOME")==NULL?"C:":getenv("HOME"), db_log); // windows*/
	
	dbglog("call: %s\n", buf);
	FILE * pipe = popen(buf, "r");
	if (!pipe) {
		ret = ERROR_PPUTIL;
		return ret;
	} else {
		get_line(pipe, buf, 64);
		if (strcmp(buf, "true")) {
			dbglog("buf: %s\n", buf);
			ret = ERROR_INSERT_DB;
			if (pipe) pclose(pipe);
			return ret;
		}
		return ret;
	}
}
/* end 2014.04.23 zhenxie insert log to db */

void get_day( char * day  )
{
	time_t tmp_time = time(NULL);
	strftime(day, 10, "%Y-%m-%d", localtime(&tmp_time));
}
