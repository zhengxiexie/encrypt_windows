#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <oci.h>

#include "crypto.h"
#include "utils.h"
#include "error.h"

typedef struct encrypt_context_cache_t encrypt_context_cache_t;
struct encrypt_context_cache_t {
    encrypt_context_t ctx;
    encrypt_context_cache_t * next;
};

struct session_cache_t {
    encrypt_context_cache_t * enc_cache;
    decrypt_context_t * dec_ctx;
    FILE * logfile;
};
typedef struct session_cache_t session_cache_t;

#define die(r) do { \
    errcode = r; \
    line = __LINE__; \
    goto error; \
} while (0)

static session_cache_t * session_cache = NULL;
static volatile int session_init_lock = 0;
static volatile int session_add_lock  = 0;

static int do_session_init() {
    int ret = 0;
    char buf[1024];
    session_cache = calloc(1, sizeof(session_cache_t));
    if (!session_cache) return ERROR_NOMEM;
	sprintf(buf, "%s/" PREFIX "/privacyprot.log", getenv("HOME")); // linux
    /*sprintf(buf, "%s/" PREFIX "/privacyprot.log", getenv("HOME")==NULL?"C:":getenv("HOME")); // windows*/
	
    session_cache->logfile = fopen(buf, "a+");
    session_cache->dec_ctx = calloc(1, sizeof(decrypt_context_t));
    if (!session_cache->dec_ctx) return ERROR_NOMEM;
    if ((ret = init_decrypt_context(session_cache->dec_ctx))) return ret;
    return 0;
}

static int session_init(OCIExtProcContext * oci_ctx) {
    int ret = 0, line = 0, errcode = 0;
    char buf[512];

    // another thread is init session_cache, wait till it is done
    if (session_init_lock) {
        while (session_init_lock);
        return 0;
    }

    session_init_lock = 1;
    if ((ret = do_session_init())) die(ret);
    session_init_lock = 0;

    if (session_cache->logfile) {
        fprintf(session_cache->logfile,
        "[%s] Session cache on %p\n",
        timestamp(buf), session_cache);
    }
    return 0;

error:
    if (session_cache && session_cache->logfile) {
        fprintf(session_cache->logfile,
            "[%s] ERROR: Cannot Session cache, Message: %s\n",
            timestamp(buf), errmsg[errcode]);
        fflush(session_cache->logfile);
    }
    if (session_cache && session_cache->dec_ctx)
        free(session_cache->dec_ctx);
    if (session_cache) free(session_cache);

    // write error mesxsages
    snprintf(buf, 1024, "[NOT A BUG] %d %s", line, errmsg[errcode]);
    OCIExtProcRaiseExcpWithMsg(oci_ctx, 20010, (text *)buf, 0);
    session_init_lock = 0;
    return errcode;
}

static int get_encrypt_ctx(OCIExtProcContext * oci_ctx,
    const char * colid, encrypt_context_t ** ret_ctx) {

    int ret = 0;
    encrypt_context_cache_t * this_ctx = NULL;
    encrypt_context_cache_t * last_ctx = NULL;

    // find cached enc_ctx
    for (this_ctx = session_cache->enc_cache; this_ctx;
         last_ctx = this_ctx, this_ctx = this_ctx->next) {
        if (0 == strcmp(colid, this_ctx->ctx.info.colid)) {
            // return cached
            dbglog("found ctx: %p\n", &this_ctx->ctx);
            *ret_ctx = &this_ctx->ctx;
            return 0;
        }
    }

    // new context
    encrypt_context_cache_t * new_ctx = calloc(1, sizeof(encrypt_context_cache_t));
    if (!new_ctx) return ERROR_NOMEM;

    if ((ret = init_encrypt_context(&new_ctx->ctx, colid))) {
        free(new_ctx);
        return ret;
    }

    if (last_ctx) {
        last_ctx->next = new_ctx;
    } else {
        session_cache->enc_cache = new_ctx;
    }

    dbglog("new ctx: %p\n", &new_ctx->ctx);
    *ret_ctx = &new_ctx->ctx;
    return 0;
}

char * ora_encrypt(OCIExtProcContext * oci_ctx, char * in, char * colid) {

    int ret = 0, line = 0, errcode = 0;

    dbglog("Called\n");
    // init session_cache if not been inited
    if ((ret = session_init(oci_ctx))) die(ret);
    dbglog("session_init()\n");

    encrypt_context_t * ctx = NULL;

    // lookup in cache
    if ((ret = get_encrypt_ctx(oci_ctx, colid, &ctx))) die(ret);
    dbglog("get_encrypt_ctx(): %p\n", ctx);

    char buf[2048];
    memset(buf, 0, sizeof(buf));
    if ((ret = do_encrypt(ctx, in, buf))) die(ret);
    char * out = OCIExtProcAllocCallMemory(oci_ctx, strlen(buf) + 1);
    strcpy(out, buf);
    return out;

error:
    if (session_cache && session_cache->logfile) {
        fprintf(session_cache->logfile,
            "[%s] ERROR: Encrypt Fail. Message: %s\n",
            timestamp(buf), errmsg[errcode]);
        fflush(session_cache->logfile);
    }
    // write error mesxsages
    snprintf(buf, 1024,
        "[NOT A BUG] %d %s", line, errmsg[errcode]);
    OCIExtProcRaiseExcpWithMsg(oci_ctx, 20010, (text *)buf, 0);
    return NULL;
}

char * ora_update(OCIExtProcContext * oci_ctx, char * in, char * colid) {
    int ret = 0, line = 0, errcode = 0;
    // init session_cache if not been inited
    if ((ret = session_init(oci_ctx))) die(ret);

    encrypt_context_t * enc_ctx = NULL;
    decrypt_context_t * dec_ctx = NULL;

    char buf[2048], buf_dec[1024];

    // lookup in cache
    if ((ret = get_encrypt_ctx(oci_ctx, colid, &enc_ctx))) die(ret);
    if (!(dec_ctx = session_cache->dec_ctx)) die(ERROR_NOMEM);

    // try decrypt first
    do_decrypt(dec_ctx, in, buf_dec);
    if ((ret = do_encrypt(enc_ctx, buf_dec, buf))) die(ret);
    char * out = OCIExtProcAllocCallMemory(oci_ctx, strlen(buf) + 1);
    strcpy(out, buf);

    return out;

error:
    if (session_cache && session_cache->logfile) {
        fprintf(session_cache->logfile,
            "[%s] ERROR: Update Fail, Message: %s\n",
            timestamp(buf), errmsg[errcode]);
        fflush(session_cache->logfile);
    }
    // write error mesxsages
    snprintf(buf, 1024,
        "[NOT A BUG] %d %s", line, errmsg[errcode]);
    OCIExtProcRaiseExcpWithMsg(oci_ctx, 20010, (text *)buf, 0);
    return NULL;
}

char * ora_decrypt(OCIExtProcContext * oci_ctx, char * in) {
    int ret = 0, line = 0, errcode = 0;
    // init session_cache if not been inited
    if ((ret = session_init(oci_ctx))) die(ret);

    decrypt_context_t * ctx = session_cache->dec_ctx;
    if (!ctx) die(ERROR_NOMEM);

    char buf[2048];
    do_decrypt(ctx, in, buf);
    char * out = OCIExtProcAllocCallMemory(oci_ctx, strlen(buf) + 1);
    strcpy(out, buf);
    return out;

error:
    OCIExtProcRaiseExcpWithMsg(oci_ctx, 20010, (text*)"Fail", 0);
    return NULL;
}

char * ora_base64_decode(OCIExtProcContext * oci_ctx, char * in) {
    int ret = 0, line = 0, errcode = 0;
    // init session_cache if not been inited
    if ((ret = session_init(oci_ctx))) die(ret);

    decrypt_context_t * ctx = session_cache->dec_ctx;
    if (!ctx) die(ERROR_NOMEM);

    char buf[2048];
    do_base64_decode(ctx, in, buf);
    char * out = OCIExtProcAllocCallMemory(oci_ctx, strlen(buf) + 1);
    strcpy(out, buf);
    return out;

error:
    OCIExtProcRaiseExcpWithMsg(oci_ctx, 20010, (text*)"Fail", 0);
    return NULL;
}
