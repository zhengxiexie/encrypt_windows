#include <oci.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

// log gile
FILE * logfile = NULL;

// error message
static char errtext[1024] = "";
static int  errcode = 0;

// OCI enviroments
static OCIEnv    * envhp = NULL;
static OCISvcCtx * svchp = NULL;
static OCIError  * errhp = NULL;

// schema
char schema[64] = "";

static const char sql_policy[] = "";

#ifndef _PREFIX
#   define PREFIX "privacy"
#else
#   define PREFIX M_STR(_PREFIX)
#endif

#define R(st) if ((ret = (st)) != OCI_SUCCESS) {\
    OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, \
        &errcode, (text *)errtext, (size_t)1024, OCI_HTYPE_ERROR);\
    if (logfile) fprintf(logfile, \
            "pputils [ERROR] line: %d, errcode: %d, msg: %s", \
            __LINE__, errcode, \
            errcode == 0? "Env ORACLE_HOME not set\n": errtext); \
    goto error; \
}

static int open_db() {
    char username[64];
    char password[64];
    char database[64];

    int ret = 0;

    if ((ret = get_dbconfig(database, username, password, schema)))
        return ret;

    R(OCIEnvCreate(&envhp, OCI_DEFAULT,
        NULL, NULL, NULL, NULL,
        0, (void **)NULL));

    R(OCIHandleAlloc((dvoid *)envhp,
        (void **)&errhp, OCI_HTYPE_ERROR,
        (size_t)0, (void **)NULL));

    R(OCIHandleAlloc((dvoid *)envhp,
        (void **)&svchp, OCI_HTYPE_SVCCTX,
        (size_t)0, (void **) NULL));

    R(OCILogon(envhp, errhp, &svchp,
        (text *)username, strlen(username),
        (text *)password, strlen(password),
        (text *)database, strlen(database)));

error:
    return ret? ERROR_DBCONN: 0;
}

static int close_db() {
    OCILogoff(svchp, errhp);
    OCIHandleFree(svchp, OCI_HTYPE_SVCCTX);
    OCIHandleFree(errhp, OCI_HTYPE_ERROR);
    return 0;
}


static int lookup_colid_in_db(const char * colid,
    char * a, char * m, char * k, int * v, int * t) {
    char sql_colid[1024];
    int ret = 0;

    sprintf(sql_colid,
        " SELECT"
        "     b.PRIVATE_KEY,"
        "     c.ALGO_FUN_NAME,"
        "     c.ALGO_MD5_CHECKSUM,"
        "     b.POLICY_VERSION,"
        "     a.COLUMN_DATA_TYPE,"
        "     a.CUR_STATUS"
        " FROM"
        "            %s.PRIVACY_PROTECT_COLUMN a"
        " INNER JOIN %s.PRIVACY_PROCESS_POLICY b"
        "         ON (a.ALGO_ID = b.ALGO_ID)"
        " INNER JOIN %s.PRIVACY_ENCODE_ALGO_MANAGE c"
        "         ON (b.ALGO_ID = c.ALGO_ID)"
        " WHERE 1 = 1"
        "     AND b.START_TIME < CURRENT_TIMESTAMP"
        "     AND b.START_TIME is NOT NULL"
        "     AND b.STATUS = 1"
        "     AND b.END_TIME is NULL"
        "     AND a.COLUMN_ID = '%s'"
        " ORDER BY b.POLICY_VERSION DESC",
        schema, schema, schema, colid);

    OCIStmt * st = NULL;

    // allocate a handler
    R(OCIHandleAlloc((dvoid *)envhp,
        (void **)&st, OCI_HTYPE_STMT, (size_t)0, (void **)NULL));

    R(OCIStmtPrepare(st, errhp,
        (text *)sql_colid, strlen(sql_colid),
        OCI_NTV_SYNTAX, OCI_DEFAULT));

    // def select list
    char key[2048], algo[MAXLEN_ALGONAME], md5sum[64];
    int  policy, type, cur_status;
    OCIDefine * defhp[6];

    R(OCIDefineByPos(st, &defhp[0], errhp,
        1, (dvoid *)key, sizeof(key), SQLT_STR, 0, 0, 0, OCI_DEFAULT));
    R(OCIDefineByPos(st, &defhp[1], errhp,
        2, (dvoid *)algo, sizeof(algo), SQLT_STR, 0, 0, 0, OCI_DEFAULT));
    R(OCIDefineByPos(st, &defhp[2], errhp,
        3, (dvoid *)md5sum, sizeof(md5sum), SQLT_STR, 0, 0, 0, OCI_DEFAULT));
    R(OCIDefineByPos(st, &defhp[3], errhp,
        4, (dvoid *)&policy, sizeof(policy), SQLT_INT, 0, 0, 0, OCI_DEFAULT));
    R(OCIDefineByPos(st, &defhp[4], errhp,
        5, (dvoid *)&type, sizeof(type), SQLT_INT, 0, 0, 0, OCI_DEFAULT));
    R(OCIDefineByPos(st, &defhp[5], errhp,
        6, (dvoid *)&cur_status, sizeof(cur_status), SQLT_INT, 0, 0, 0, OCI_DEFAULT));

    // run the sql
    R(OCIStmtExecute(svchp, st, errhp, 1, 0,
        (OCISnapshot *)NULL, (OCISnapshot *)NULL, OCI_DEFAULT));

    // fetch the result
    // R(OCIStmtFetch(st, errhp, 1, OCI_FETCH_NEXT, OCI_DEFAULT));

    static const int E[] = {0, ERROR_DELETE, ERROR_UPDATING};
    if (cur_status) return E[cur_status];

    // return the result
    strcpy(k, key);
    strncpy(a, algo, MAXLEN_ALGONAME);
    strncpy(m, md5sum, 32);
    *v = policy;
    *t = type;
    ret = 0;

error:
    if (st) OCIHandleFree(st, OCI_HTYPE_STMT);
    return ret? ERROR_NOKEY: 0;
}

static int lookup_policy_in_db(int policy, char * a, char * k) {
    char sql[1024], algo[MAXLEN_ALGONAME], key[2048];
    int ret = 0;

    sprintf(sql,
        " SELECT b.ALGO_FUN_NAME, a.PRIVATE_KEY"
        " FROM %s.PRIVACY_PROCESS_POLICY a"
        " INNER JOIN %s.PRIVACY_ENCODE_ALGO_MANAGE b"
        " ON (a.ALGO_ID = b.ALGO_ID)"
        " WHERE a.POLICY_VERSION = %d",
        schema, schema, policy);

    OCIStmt * st = NULL;

    // allocate a handler
    R(OCIHandleAlloc((dvoid *)envhp,
        (void **)&st, OCI_HTYPE_STMT, (size_t)0, (void **)NULL));

    R(OCIStmtPrepare(st, errhp,
        (text *)sql, strlen(sql), OCI_NTV_SYNTAX, OCI_DEFAULT));

    // define select list
    OCIDefine * defhp[2];

    R(OCIDefineByPos(st, &defhp[1], errhp,
        1, (dvoid *)algo, MAXLEN_ALGONAME, SQLT_STR, 0, 0, 0, OCI_DEFAULT));
    R(OCIDefineByPos(st, &defhp[0], errhp,
        2, (dvoid *)key, 2040, SQLT_STR, 0, 0, 0, OCI_DEFAULT));

    // run the sql
    R(OCIStmtExecute(svchp, st, errhp, 1, 0,
        (OCISnapshot *)NULL, (OCISnapshot *)NULL, OCI_DEFAULT));

    // return the result
    strncpy(a, algo, MAXLEN_ALGONAME);
    strcpy(k, key);
    ret = 0;

error:
    if (st) OCIHandleFree(st, OCI_HTYPE_STMT);
    return ret? ERROR_NOKEY: 0;
}

static int update_column_status(const char * colid, int status) {
    char sql[1024];
    int  ret = 0;

    snprintf(sql, 1024,
        " UPDATE %s.PRIVACY_PROTECT_COLUMN a"
        " SET a.CUR_STATUS = %d"
        " WHERE a.COLUMN_ID = '%s'",
        schema, status, colid);

    OCIStmt * st = NULL;

    // allocate a handler
    R(OCIHandleAlloc((dvoid *)envhp,
        (void **)&st, OCI_HTYPE_STMT, (size_t)0, (void **)NULL));

    R(OCIStmtPrepare(st, errhp,
        (text *)sql, strlen(sql), OCI_NTV_SYNTAX, OCI_DEFAULT));

    // run the sql
    R(OCIStmtExecute(svchp, st, errhp, 1, 0,
        (OCISnapshot *)NULL, (OCISnapshot *)NULL, OCI_DEFAULT));

    ret = 0;

error:
    if (st) OCIHandleFree(st, OCI_HTYPE_STMT);
    return ret? ERROR_NOKEY: 0;
}

#define die(n) do { \
    errcode = n; \
    goto error; \
} while (0)

int main(int argc, char *argv[]) {
    int ret = 0, errcode = 0;
    char buf[1024];
    char key[1024] =  "";
    char algo[MAXLEN_ALGONAME] = "";
    char md5[64] = "";
    int policy = 0;
    int type = 0;

	sprintf(buf, "%s/%s/privacyprot.log", getenv("HOME"), PREFIX); // linux
    /*sprintf(buf, "%s/%s/privacyprot.log", getenv("HOME")==NULL?"C:":getenv("HOME"), PREFIX); // windows*/
	
    logfile = fopen(buf, "a+");

    if (getenv("TERM")) die(ERROR_DBUTILS_SHELL);
    if (argc < 3) die(ERROR_DBUTILS_PARAM);
    if ((ret = open_db())) die(ret);

    ret = 0;

    if (0 == strcasecmp(argv[1], "policy")) {
        policy = atoi(argv[2]);
        if ((ret = lookup_policy_in_db(policy, algo, key))) die(ret);
        if (key[0]) {
            printf("OK\n");
            printf("%s\n", algo);
            printf("%s\n", key);
        } else {
            die(ERROR_NOKEY);
        }
    } else if (0 == strcasecmp(argv[1], "colid")) {
        if ((ret = lookup_colid_in_db(argv[2], algo, md5, key, &policy, &type)))
            die(ret);
        if (key[0]) {
            printf("OK\n");
            printf("%s\n", algo);
            printf("%s\n", md5);
            printf("%s\n", key);
            printf("%d\n", policy);
            printf("%d\n", type);
        } else {
            die(ERROR_NOKEY);
        }
    } else if (0 == strcasecmp(argv[1], "update")) {
        if ((ret == update_column_status(argv[2], atoi(argv[3])))) die(ret);
        printf("OK\n");
    } else {
        die(ERROR_DBUTILS_PARAM);
    }

error:
    if (logfile) fclose(logfile);
    close_db();
    if (errcode) {
        printf("Error\n");
        printf("%d\n", errcode);
        printf("%s\n", errmsg[errcode]);
    }
    return errcode;
}

