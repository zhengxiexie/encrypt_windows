#include <stdint.h>
#include <string.h>
#ifndef NO_LIBDL
#include <dlfcn.h>
#endif
#include <stdio.h>

#include "crypto.h"
#include "utils.h"

// import all crypto implementation
#include "crypto_impl.c"

static const struct  crypto_t {
    const char * name;
    ctx_new_func  * ctx_new;
    ctx_free_func * ctx_free;
    crypto_func   * enc_func;
    crypto_func   * dec_func;
} crypto_methods[] = {
    {"stream", basic_init,   basic_free,   stream_cipher, stream_cipher},
    {"shift",  basic_init,   basic_free,   shift_encrypt, shift_decrypt},
    {"map",    map_ctx_init, basic_free,   map_encrypt,   map_decrypt},
    {"AES",    EVP_ctx_init, EVP_ctx_free, encrypt_aes,   decrypt_aes},
    {"3DES",   EVP_ctx_init, EVP_ctx_free, encrypt_3des,  decrypt_3des},
    {"DES",    EVP_ctx_init, EVP_ctx_free, encrypt_des,   decrypt_des},
    {"RC4",    EVP_ctx_init, EVP_ctx_free, encrypt_rc4,   decrypt_rc4},
	/* beg 2014.05.06 zhengxie if compiled by cygwin on windows, must comment this, don't ask me why, it confused me 5 days, shit!  */
	//{"RC5",    EVP_ctx_init, EVP_ctx_free, encrypt_rc5,   decrypt_rc5},
    {NULL, NULL, NULL, NULL, NULL}, // only chaos beyond this fine line
};

struct userdef_t {
    void          * handle;
    crypto_func   * cipher;
    ctx_free_func * ctx_free;
};

static const char  * search_path[] = {
    "%s/" PREFIX "/privacy_user_%s.so",
    "%s/" PREFIX "/user/%s.so",
    NULL,
};

static int read_column_info_pputil(column_info_t * info, const char * colid);

static int read_column_info_pputil(column_info_t * info, const char * colid) {
    char buf[1024];
    int ret = 0;
    snprintf(buf, 1024, "%s/" PREFIX "/pputil colid %s", getenv("HOME"), colid);

	dbglog("call: %s\n", buf);

    FILE * pipe = popen(buf, "r");
    if (!pipe) {
        ret = ERROR_PPUTIL;
    } else {
        get_line(pipe, buf, 64);
        if (strcmp(buf, "OK")) {
            get_line(pipe, buf, 32);
            ret = atoi(buf);
            if (!ret) ret = ERROR_PPUTIL;
        } else {
            get_line(pipe, buf, 64);
            strncpy(info->algo_name, buf, MAXLEN_ALGONAME);
            get_line(pipe, buf, 64);
            memcpy(info->md5, buf, 32);
            get_line(pipe, buf, 1024);
            base64_decode(info->key, buf);
            get_line(pipe, buf, 64);
            info->policy = atoi(buf);
            get_line(pipe, buf, 64);
            info->type = atoi(buf);
            get_line(pipe, buf, 64);
            info->hold_bytes = atoi(buf);
            // copy colid into column info
            strcpy(info->colid, colid);
        }
    }
    if (pipe) pclose(pipe);
    return ret;
}

// init encrypt context using algo name and key
int init_encrypt_context(encrypt_context_t * ctx, const char * colid) {
    int ret = 0;

    // read column info
    column_info_t * info = &ctx->info;
    if ((ret = read_column_info_pputil(info, colid))) return ret;

    /*dbglog("passing read_column_info\n");*/

    // then, lookup in what we already implemented
    const crypto_t * builtin = NULL;
    for (builtin = crypto_methods; builtin->name; builtin++) {
        if (0 == strcasecmp(builtin->name, info->algo_name)) break;
    }

    if (builtin) {
        ctx->how = CIPHER_BUILTIN;
        ctx->impl.builtin = builtin;
        ctx->enc_ctx = builtin->ctx_new(info->key);
    } else {
#ifndef NO_LIBDL
        // try to find userdefined algorithm
        char buf[256];
		/*const char * home_dir = getenv("HOME"); // linux*/
		const char * home_dir = getenv("HOME")==NULL?"C:":getenv("HOME"); // windows
        void * handle = NULL;
        int found_userdef = 0, i = 0;

        for (i = 0; search_path[i]; i++) {
            snprintf(buf, 255, search_path[i], home_dir, info->algo_name);
            handle = dlopen(buf, RTLD_LAZY);
            if (handle && check_file_md5(buf, info->md5)) {
                // get new free enc form .so
                crypto_func   * enc_func = dlsym(handle, "encrypt");
                ctx_new_func  * ctx_new  = dlsym(handle, "ctx_new");
                ctx_free_func * ctx_free = dlsym(handle, "ctx_free");

                if (enc_func && ctx_new && ctx_free) {
                    ctx->how = CIPHER_USERDEF;
                    userdef_t * userdef = calloc(1, sizeof(userdef_t));
                    userdef->handle   = handle;
                    userdef->cipher   = enc_func;
                    userdef->ctx_free = ctx_free;
                    ctx->impl.userdef = userdef;
                    ctx->enc_ctx = ctx_new(info->key);
                    found_userdef = 1;
                    break;
                }
                dlclose(handle);
            }
        }

        if (!found_userdef) return ERROR_USERLIB;
#else
        return ERROR_NOLIBDL;
#endif
    }

    return 0;
}

void destroy_encrypt_context(encrypt_context_t * ctx) {
    dbglog("freeing ctx: %p, real ctx: %p\n", ctx, ctx->enc_ctx);
    if (ctx->enc_ctx) {
        switch (ctx->how) {
        case CIPHER_BUILTIN:
            dbglog("freeing builtin: %s\n", ctx->impl.builtin->name);
            if (ctx->enc_ctx) ctx->impl.builtin->ctx_free(ctx->enc_ctx);
            break;
        case CIPHER_USERDEF:
            ctx->impl.userdef->ctx_free(ctx->enc_ctx);
#ifndef NO_LIBDL
            dlclose(ctx->impl.userdef->handle);
#endif
            free(ctx->impl.userdef);
            break;
        }
    }
    free(ctx);
    dbglog("encrypt context free done!\n");
}

int do_encrypt(encrypt_context_t * ctx, const char * in, char * out)
{
    int in_len = strlen(in), ret = 0, out_len = 0;
    uint8_t buf[1024], buf_enc[1024];
    const uint8_t * to_be_enc = NULL;

    int enc_len = 0;
    memset(buf, 0, sizeof(buf));
    memset(buf_enc, 0, sizeof(buf_enc));

    column_info_t * info = &ctx->info;
    if (info->hold_bytes < in_len) {
		dbglog("source data[%s] len[%d]\n", in, in_len);

        // keep first hold_bytes byte plaintext
        strncpy(out, in, info->hold_bytes);

        out[info->hold_bytes + 1] = info->policy / 255 + 1;
        out[info->hold_bytes + 2] = info->policy % 255 + 1;

        // compress?
        switch (info->type) {
        case TYPE_NUMSTRING:
            out[info->hold_bytes] = 0x04;
			if ((ret = compress_numstring(in + info->hold_bytes, buf)))
                    return ret;
            to_be_enc = buf;
			enc_len = (in_len - info->hold_bytes + 1) / 2;
            break;
        case TYPE_STRING:
            out[info->hold_bytes] = 0x03;
			to_be_enc = ((uint8_t *)in + info->hold_bytes);
			enc_len = in_len - info->hold_bytes;
        }


        // encrypt the rest
        crypto_func * f = (ctx->how == CIPHER_BUILTIN)?
                           ctx->impl.builtin->enc_func:
                           ctx->impl.userdef->cipher;
        out_len = f(ctx->enc_ctx, to_be_enc, enc_len, (uint8_t *)buf_enc);

		dbglog("after encrypt\n");
        loghex( buf_enc, out_len);

        // base64 encode it and store it into out
        int base64_len = base64_encode(out + info->hold_bytes + 3, (uint8_t *)buf_enc, out_len);

		dbglog("after base64_encode\n");
		dbglog("base64[%s] len[%d]\n", out + info->hold_bytes + 3, base64_len);

		dbglog("ultimate data to db\n");
		dbglog("destination data[%s] len[%d]\n", out, strlen(out));

    } else {
        strcpy(out, in);
    }

	dbglog("encrypt done!\n");
    return 0;
}

// decrypt API

int init_decrypt_context( decrypt_context_t * ctx) {
    // doing nothing
    ctx->policy = -1;
    return 0;
}

void destroy_decrypt_context(decrypt_context_t * ctx) {
    while (ctx) {
        switch (ctx->how) {
        case CIPHER_BUILTIN:
            if (ctx->dec_ctx) ctx->impl.builtin->ctx_free(ctx->dec_ctx);
            break;
        case CIPHER_USERDEF:
            if (ctx->dec_ctx) ctx->impl.userdef->ctx_free(ctx->dec_ctx);
            if (ctx->impl.userdef) {
#ifndef NO_LIBDL
                if (ctx->impl.userdef->handle) dlclose(ctx->impl.userdef->handle);
#endif
                free(ctx->impl.userdef);
            }
            break;
        }
        decrypt_context_t * this_ctx = ctx;
        ctx = this_ctx->next;
        free(this_ctx);
    }
}

static decrypt_context_t * read_policy_pputil(int policy) {
    char buf[2048], algorithm[MAXLEN_ALGONAME];
    uint8_t key[KEY_SIZE];

    // read policy info from pputil
    int policy_found = 0;
	/*sprintf(buf, "%s/" PREFIX "/pputil policy %d", getenv("HOME"), policy); // linux*/
	sprintf(buf, "%s/" PREFIX "/pputil policy %d", getenv("HOME")==NULL?"C:":getenv("HOME"), policy); // windows
	dbglog("call: %s\n", buf);

    FILE * pipe = popen(buf, "r");
    if (!pipe) return NULL;
    get_line(pipe, buf, 10);
    if (0 == strcmp(buf, "OK")) {
        get_line(pipe, algorithm, MAXLEN_ALGONAME);
        get_line(pipe, buf, 1023);
        base64_decode(key, buf);
        policy_found = 1;
    }
    pclose(pipe);
    if (!policy_found) return NULL;

    const crypto_t * builtin = NULL;
    decrypt_context_t * ret = NULL;
    // lookup for alogrithm in builtin implement
    for (builtin = crypto_methods; builtin->name; builtin++) {
        if (0 == strcasecmp(algorithm, builtin->name)) break;
    }

    if (builtin) {
        ret = calloc(1, sizeof(decrypt_context_t));
        ret->policy       = policy;
        ret->impl.builtin = builtin;
        dbglog("DECRYPT: calling init\n");
        ret->dec_ctx      = builtin->ctx_new(key);
        ret->how          = CIPHER_BUILTIN;
    } else {
#ifndef NO_LIBDL
        // try to load userdef lib
		/*const char * home_dir = getenv("HOME"); // linux*/
		const char * home_dir = getenv("HOME")==NULL?"C:":getenv("HOME"); // windows
        void * handle = NULL;
        int found_userdef = 0, i = 0;

        for (i = 0; search_path[i]; i++) {
            snprintf(buf, 255, search_path[i], home_dir, algorithm);
            handle = dlopen(buf, RTLD_LAZY);
            if (handle) {
                // get new free enc form .so
                crypto_func   * dec_func = dlsym(handle, "decrypt");
                ctx_new_func  * ctx_new  = dlsym(handle, "ctx_new");
                ctx_free_func * ctx_free = dlsym(handle, "ctx_free");

                if (dec_func && ctx_new && ctx_free) {
                    ret = calloc(1, sizeof(decrypt_context_t));
                    ret->how = CIPHER_USERDEF;
                    userdef_t * userdef = calloc(1, sizeof(userdef_t));
                    userdef->handle   = handle;
                    userdef->cipher   = dec_func;
                    userdef->ctx_free = ctx_free;
                    ret->impl.userdef = userdef;
                    ret->dec_ctx = ctx_new(key);
                    found_userdef = 1;
                    break;
                }
                dlclose(handle);
            }
        }

        if (!found_userdef) return NULL;
#else
        return NULL;
#endif
    }

    return ret;
}

static decrypt_context_t * find_or_new_dec_ctx(
    decrypt_context_t * ctx, int policy) {

    decrypt_context_t * this_ctx = NULL;
    decrypt_context_t * last_ctx = NULL;

    for (this_ctx = ctx;
         this_ctx;
         last_ctx = this_ctx, this_ctx = this_ctx->next) {
        if (this_ctx->policy == policy) return this_ctx;
    }

    decrypt_context_t * new_ctx = read_policy_pputil(policy);
    dbglog("new ctx at %p\n", new_ctx);
    if (new_ctx) last_ctx->next = new_ctx;
    return new_ctx;
}

int do_decrypt(decrypt_context_t * ctx, const char * in, char * out)
{
    uint8_t buf[2048], buf_dec[2048];
    int  data_type = 0, in_len = 0, policy = 0, encp = 0, enc_len = 0;

	/* beg 2014.04.23 zhengxie modify a bug */
	int found_policy = 0;
	/* end 2014.04.23 zhengxie modify a bug */

    // in sanity check... Magic here
    if (!in) goto return_plain;
    in_len = strlen(in);
    if (in_len < 4) goto return_plain;

    // findout where to start decrypt
    for (encp = 0; encp < in_len - 3; encp++)
   	{
        if (in[encp] == 0x03 || in[encp] == 0x04) {
            data_type = in[encp];
            policy   = ((uint8_t)in[encp + 1] - 1) * 255
                     + ((uint8_t)in[encp + 2] - 1);

			/* beg 2014.04.23 zhengxie modify a bug */
			found_policy = 1;
			/* end 2014.04.23 zhengxie modify a bug */
            break;
        }
    }

	/* beg 2014.04.23 zhengxie modify a bug */
	if( !found_policy ){
		goto return_plain;
	}
	/* end 2014.04.23 zhengxie modify a bug */

    decrypt_context_t * dec_ctx = find_or_new_dec_ctx(ctx, policy);

    if (!dec_ctx) goto return_plain;

    // copy the plain part
    strncpy(out, in, encp);
    memset(buf,     0, sizeof(buf));
    memset(buf_dec, 0, sizeof(buf_dec));

	dbglog("source data[%s] len[%d]\n", in, in_len);

    // base64 decode
    enc_len = base64_decode(buf, in + encp + 3);
	dbglog("after base64_decode\n");
    loghex(buf, enc_len);

    // and decrypt
    crypto_func * f = dec_ctx->how == CIPHER_BUILTIN?
                      dec_ctx->impl.builtin->dec_func:
                      dec_ctx->impl.userdef->cipher;
    f(dec_ctx->dec_ctx, buf, enc_len, buf_dec);

    // flatten?
    if (data_type == 0x03) {
        strcpy(out + encp, (const char *)buf_dec);
    } else if (data_type == 0x04) {
        flatten_numstring(buf_dec, out + encp);
    }

	dbglog("after decrypt\n");
	dbglog("destination data[%s] len[%d]\n", out, strlen(out) );
	dbglog("decrypt done!\n");
    return 0;
return_plain:
    strcpy(out, in);
    return 0;
}

int do_base64_decode(decrypt_context_t * ctx, const char * in, char * out)
{
    uint8_t buf[2048], buf_dec[2048];
    int  data_type = 0, in_len = 0, policy = 0, encp = 0, enc_len = 0;

	/* beg 2014.04.23 zhengxie modify a bug */
	int found_policy = 0;
	/* end 2014.04.23 zhengxie modify a bug */

    // in sanity check... Magic here
    if (!in) goto return_plain;
    in_len = strlen(in);
    if (in_len < 4) goto return_plain;

    // findout where to start decrypt
    for (encp = 0; encp < in_len - 3; encp++)
   	{
        if (in[encp] == 0x03 || in[encp] == 0x04) {
            data_type = in[encp];
            policy   = ((uint8_t)in[encp + 1] - 1) * 255
                     + ((uint8_t)in[encp + 2] - 1);

			/* beg 2014.04.23 zhengxie modify a bug */
			found_policy = 1;
			/* end 2014.04.23 zhengxie modify a bug */
            break;
        }
    }

	/* beg 2014.04.23 zhengxie modify a bug */
	if( !found_policy ){
		goto return_plain;
	}
	/* end 2014.04.23 zhengxie modify a bug */

    decrypt_context_t * dec_ctx = find_or_new_dec_ctx(ctx, policy);

    if (!dec_ctx) goto return_plain;

    // copy the plain part
    strncpy(out, in, encp);
    memset(buf,     0, sizeof(buf));
    memset(buf_dec, 0, sizeof(buf_dec));

	dbglog("source data[%s] len[%d]\n", in, in_len);

    // base64 decode
    enc_len = base64_decode(buf, in + encp + 3);
	dbglog("after base64_decode\n");

    char __bytes[2048]; \
    int __i = 0;
    for (__i = 0; __i < (enc_len); __i++) {
        __bytes[__i * 2 + 0] = "0123456789abcdef"[(int)buf[__i] / 16];
        __bytes[__i * 2 + 1] = "0123456789abcdef"[(int)buf[__i] % 16];
    }
    __bytes[__i * 2] = 0;
    dbglog("cypher[%s] len[%d]\n", __bytes, enc_len);

	strcpy(out + encp, (const char *)__bytes);

    // flatten?
    /*if (data_type == 0x03) {*/
        /*strcpy(out + encp, (const char *)__bytes);*/
    /*} else if (data_type == 0x04) {*/
        /*flatten_numstring(buf_dec, out + encp);*/
    /*}*/

	dbglog("after do_base64_decode\n");
	dbglog("destination data[%s] len[%d]\n", out, strlen(out) );
	dbglog("do_base64_decode done!\n");
    return 0;
return_plain:
    strcpy(out, in);
    return 0;
}
