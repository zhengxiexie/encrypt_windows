/* SHOULD NOT BE INCLUDED IN ANY FILE OTHER THAN crypto.c */

#include <openssl/evp.h>

#include "utils.h"

// algorithm implemented by Openssl EVP {{{

struct evp_ctx_t {
    EVP_CIPHER_CTX * ctx;
    unsigned char salt[16];
    uint8_t key[256];
};

enum CIPHER_ACTION {
    CIPHER_decrypt = 0,
    CIPHER_encrypt = 1,
};

static size_t md5hash(const uint8_t * in, uint8_t * out) {
    unsigned int md_len = 0;
    EVP_MD_CTX * md5_ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(md5_ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(md5_ctx, in, KEY_SIZE);
    EVP_DigestFinal(md5_ctx, out, &md_len);
    EVP_MD_CTX_destroy(md5_ctx);
    return md_len;
}

// universal openssl wrapper
static size_t openssl_encrypt(
    void * cipher_ctx, const EVP_CIPHER * ct, enum CIPHER_ACTION action,
    const uint8_t * in, size_t len_in, uint8_t * out) {

    unsigned char  * salt = ((struct evp_ctx_t *)cipher_ctx)->salt;
    uint8_t        * key  = ((struct evp_ctx_t *)cipher_ctx)->key;
    EVP_CIPHER_CTX * ctx  = ((struct evp_ctx_t *)cipher_ctx)->ctx;
    int temp_len = 0, len = 0;

    EVP_CipherInit_ex(ctx, ct, NULL, key, salt, action);
    EVP_CipherUpdate(ctx, out, &temp_len, (uint8_t *)in, len_in);
    len += temp_len;
    EVP_CipherFinal_ex(ctx, out + len, &temp_len);
    len += temp_len;
    EVP_CIPHER_CTX_cleanup(ctx);
    out[len] = 0;
    return len;
}

#define def_cipher_func(name, type) \
static int encrypt_##name(void * ctx, \
    const uint8_t * in, size_t len_in, uint8_t * out) { \
    return openssl_encrypt(ctx, type(), CIPHER_encrypt, in, len_in, out); \
} \
\
static int decrypt_##name(void * ctx, \
    const uint8_t * in, size_t len_in, uint8_t * out) { \
    return openssl_encrypt(ctx, type(), CIPHER_decrypt, in, len_in, out); \
}

def_cipher_func(aes,  EVP_aes_256_cbc);
def_cipher_func(des,  EVP_des_cbc);
def_cipher_func(3des, EVP_des_ede3_cbc);
def_cipher_func(rc4,  EVP_rc4);
/* beg 2014.05.06 zhengxie if compiled by cygwin on windows, must comment this, don't ask me why, it confused me 5 days, shit!  */
/*def_cipher_func(rc5,  EVP_rc5_32_12_16_cbc);*/

static void * EVP_ctx_init(const uint8_t * key) {
    struct evp_ctx_t * evp_ctx = calloc(1, sizeof(struct evp_ctx_t));
    evp_ctx->ctx = EVP_CIPHER_CTX_new();
    md5hash(key, evp_ctx->salt);
    return (void *) evp_ctx;
}

static void EVP_ctx_free(void * evp_ctx) {
    if (evp_ctx) {
        EVP_CIPHER_CTX_free(((struct evp_ctx_t *)evp_ctx)->ctx);
        free(evp_ctx);
    }
}

// }}}

// simple homebrew algorithm {{{

// Stream Cipher implemenataion
// slightly modified to avoid 0x00 in encrypted string
static int stream_cipher(void * ctx,
    const uint8_t * in, size_t in_len, uint8_t * out) {

    int p = 0, pk = 0;
    uint8_t * key = (uint8_t *) ctx;
    uint8_t salt = first_salt(key);
	/* beg 2014.04.23 zhengxie modify algorithm bug */
    /*for (p = pk = 0; in[p]; p++, pk++) {*/
	for (p = pk = 0; p < in_len; p++, pk++) {
	/* end 2014.04.23 zhengxie modify algorithm bug */
        // need another salt?
        if (pk == KEY_SIZE) {
            pk = 0;
            salt = next_salt(salt);
        }
        out[p] = salt ^ in[p] ^ key[pk];
    }
    out[p] = 0;
    return p;
}

// Shift Cipher implemenataion
// slightly modified to avoid 0x00 in encrypted string
static int shift_encrypt(void * ctx,
    const uint8_t * in, size_t in_len, uint8_t * out) {

    int p = 0, pk = 0;
    uint8_t * key = (uint8_t *) ctx;
    uint8_t salt = first_salt(key);

    dbglog("==============\n");
	/* beg 2014.04.23 zhengxie modify algorithm bug */
    /*for (p = pk = 0; in[p]; p++, pk++) {*/
	for (p = pk = 0; p < in_len; p++, pk++) {
	/* end 2014.04.23 zhengxie modify algorithm bug */
        // need another salt?
        if (pk == KEY_SIZE) {
            pk = 0;
            salt = next_salt(salt);
        }

        out[p] = (in[p] + key[pk] + salt) & 0xff;
        dbglog("-- %02x + %02x + %02x = %02x\n", salt, in[p], key[pk], out[p]);
    }

    out[p] = 0;
    return p;
}

static int shift_decrypt(void * ctx,
    const uint8_t * in, size_t in_len, uint8_t * out) {
    int p = 0, pk = 0;
    uint8_t * key = (uint8_t *) ctx;
    uint8_t salt = first_salt(key);

	/* beg 2014.04.23 zhengxie modify algorithm bug */
    /*for (p = pk = 0; in[p]; p++, pk++) {*/
    for (p = pk = 0; p < in_len; p++, pk++) {
	/* end 2014.04.23 zhengxie modify algorithm bug */
        // need another salt?
        if (pk == KEY_SIZE) {
            pk = 0;
            salt = next_salt(salt);
        }
        out[p] = (in[p] + (256 - salt) + (256 - key[pk])) & 0xff;
    }
    out[p] = 0;
    return p;
}

// map Cipher implemenataion
// slightly modified to avoid 0x00 in encrypted string
struct map_ctx_t {
    uint8_t map[KEY_SIZE];
    uint8_t rmap[KEY_SIZE];
};

static int map_encrypt(void * ctx,
    const uint8_t * in, size_t in_len, uint8_t * out) {
    int p = 0;
    uint8_t * map = ((struct map_ctx_t *)ctx)->map;
	/* beg 2014.04.23 zhengxie modify algorithm bug */
    /*for (p =  0; in[p]; p++) out[p] = map[in[p]];*/
    for (p =  0; p < in_len; p++) out[p] = map[in[p]];
	/* end 2014.04.23 zhengxie modify algorithm bug */
    out[p] = 0;
    return p;
}

static int map_decrypt(void * ctx,
    const uint8_t * in, size_t in_len, uint8_t * out) {
    int p = 0;
    uint8_t * rmap = ((struct map_ctx_t *)ctx)->rmap;
	/* beg 2014.04.23 zhengxie modify algorithm bug */
    /*for (p = 0; in[p]; p++) out[p] = rmap[in[p]];*/
    for (p = 0; p < in_len; p++) out[p] = rmap[in[p]];
	/* end 2014.04.23 zhengxie modify algorithm bug */
    out[p] = 0;
    return p;
}

static void * map_ctx_init(const uint8_t * key) {
    struct map_ctx_t * ctx = calloc(1, sizeof(struct map_ctx_t));
    int p = 0;
    // salt forward map
    memcpy(ctx->map, key, KEY_SIZE);
    // construct a reverse map
    for (p = 0; p < KEY_SIZE; p++) ctx->rmap[key[p]] = p;
    return (void *)ctx;
}

// basic init ctx and free ctx function
static void * basic_init(const uint8_t * key) {
    uint8_t * ctx = calloc(KEY_SIZE, sizeof(uint8_t));
    memcpy(ctx, key, KEY_SIZE);
    return (void *) ctx;
}

static void basic_free(void * ctx) {
    if (ctx) free(ctx);
    dbglog("basic free done!\n");
}

// }}}

// continued in crypto.c
