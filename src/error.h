#ifndef _ERROR_H_
#define _ERROR_H_

extern const char * errmsg[];

#define ERROR_DBCONN        (1)
#define ERROR_NOKEY         (2)
#define ERROR_USERLIB       (3)
#define ERROR_USERFUN       (4)
#define ERROR_NONNUM        (5)
#define ERROR_NULLCOLID     (6)
#define ERROR_CFGFILE       (7)
#define ERROR_PPUTIL        (8)
#define ERROR_PPUTIL_PARAM  (9)
#define ERRORPPUTIL_SHELL  (10)
#define ERROR_MD5           (11)
#define DEBUGBP             (12)
#define ERROR_DELETE        (13)
#define ERROR_UPDATING      (14)
#define ERROR_UPDATE_STATUS (15)
#define ERROR_NOMEM         (16)
#define ERROR_ALREADY_ENC   (17)
#define ERROR_INSERT_DB     (18)
#define ERROR_NOLIBDL     (19)
#endif
