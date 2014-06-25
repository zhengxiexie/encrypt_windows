#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "utils.h"

// proto for encrypt and decrypt function, return LENGTH of encrypted message
typedef int crypto_func(void * ctx, const uint8_t * in, size_t in_len, uint8_t * out);
// create new context for BOTH encrypt and destroy
typedef void * ctx_new_func(const uint8_t * key);

// free ctx
typedef void ctx_free_func(void * ctx);

enum how_cipher_impl {
    CIPHER_BUILTIN = 0,
    CIPHER_USERDEF = 1,
};

typedef enum how_cipher_impl how_cipher_impl;

// for crypto implementation, detail should not be exposed
typedef struct crypto_t crypto_t;

// used in user defined crypto method
typedef struct userdef_t userdef_t;

// store column information
struct column_info_t {
    uint8_t key[KEY_SIZE];
    char    colid[40];
    char    md5[32];
    char    algo_name[MAXLEN_ALGONAME];
    int     hold_bytes;
    int     policy;
    enum { TYPE_NUMSTRING = 1, TYPE_STRING = 2 } type;
};
typedef struct column_info_t column_info_t;

// store context for encrypt
struct encrypt_context_t {
    column_info_t info;
    union {
        const crypto_t * builtin;
        userdef_t      * userdef;
    } impl;
    how_cipher_impl how;
    void * enc_ctx;
};
typedef struct encrypt_context_t encrypt_context_t;

// encrypt related method
int init_encrypt_context(encrypt_context_t * ctx, const char * colid);
void destroy_encrypt_context(encrypt_context_t * ctx);
int do_encrypt(encrypt_context_t * ctx, const char * in, char * out);

// cache policy info for in a chain
typedef struct decrypt_context_t decrypt_context_t;
struct decrypt_context_t {
    int  policy;
    union {
        const crypto_t * builtin;
        userdef_t      * userdef;
    } impl;
    how_cipher_impl how;
    void * dec_ctx;
    decrypt_context_t * next;
 };

// encrypt related method
int init_decrypt_context(decrypt_context_t * ctx);
void destroy_decrypt_context(decrypt_context_t * ctx);
int do_decrypt(decrypt_context_t * ctx, const char * in, char * out);

// public method
int do_base64_decode(decrypt_context_t * ctx, const char * in, char * out);
#endif
