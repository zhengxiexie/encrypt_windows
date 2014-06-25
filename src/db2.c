#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sqludf.h>
#include <time.h>
#include <stdlib.h>

#include "crypto.h"
#include "error.h"
#include "utils.h"

struct local_t {
    FILE * logfile;
    time_t begin_time;
    time_t end_time;
    uint64_t row_count;
    encrypt_context_t * enc_ctx;
    decrypt_context_t * dec_ctx;
};

#define die(r) do { \
    errcode = r; \
    line = __LINE__; \
    goto error; \
} while (0)

void SQL_API_FN db2_update(
    SQLUDF_VARCHAR * text,
    SQLUDF_VARCHAR * colid,
    SQLUDF_VARCHAR * out,
    SQLUDF_NULLIND * text_null,
    SQLUDF_NULLIND * colid_null,
    SQLUDF_NULLIND * out_null,
    SQLUDF_TRAIL_ARGS_ALL)
{

    // For error handling
    int line = 0, errcode = 0, ret = 0;

    // restore enviroment stored in SCRATCHPAD
    struct local_t    * l   = (struct local_t *)SQLUDF_SCRAT->data;
    encrypt_context_t * enc_ctx = l->enc_ctx;
    decrypt_context_t * dec_ctx = l->dec_ctx;
    char buf[1024];
	char db_log[1024];

    if (*colid_null || !colid[0]) die(ERROR_NULLCOLID);

    switch (SQLUDF_CALLT)
   	{
        case SQLUDF_FIRST_CALL:
			dbglog("enter into db2_update\n");
            // First call, init everything
            memset(l, 0, sizeof(struct local_t));
			/*sprintf(buf, "%s/" PREFIX "/privacyprot.log", getenv("HOME")); // linux*/
			sprintf(buf, "%s/" PREFIX "/privacyprot.log", getenv("HOME")==NULL?"C:":getenv("HOME")); // windows
            l->logfile    = fopen(buf, "a+");
            l->begin_time = time(NULL);

            // init encrypt context
            if (!(enc_ctx = calloc(1, sizeof(encrypt_context_t))))
                    die(ERROR_NOMEM);
            if ((ret = init_encrypt_context(enc_ctx, colid))) die(ret);
            l->enc_ctx = enc_ctx;

			dbglog("init encrypt context done!\n");

            // init decrypt context
            if (!(dec_ctx = calloc(1, sizeof(decrypt_context_t))))
                    die(ERROR_NOMEM);
            if ((ret = init_decrypt_context(dec_ctx))) die(ret);
            l->dec_ctx = dec_ctx;

			dbglog("init decrypt context done!\n");

			/* beg 2014.04.23 zhengxie insert log to db */
			sprintf( db_log,
                    "\"[%s] Starting UPDATE colid: %s, "
                    "Algorithm: %s, Policy: %d, hold %d byte(s), "
                    "md5: %s, compressing: %s\"\n",
                    timestamp(buf), colid,
                    enc_ctx->info.algo_name, enc_ctx->info.policy,
                    enc_ctx->info.hold_bytes,
                    enc_ctx->info.md5[0]? enc_ctx->info.md5: "builtin",
                    enc_ctx->info.type == TYPE_NUMSTRING? "yes": "no");

			INSERT_DB_LOG( db_log );
			/* end 2014.04.23 zhengxie insert log to db */

            // write log
            if (l->logfile) {
                fputs( db_log, l->logfile );
                fflush(l->logfile);
            }

        case SQLUDF_NORMAL_CALL:
            *out_null = 0;
            l->row_count++;
			/* beg 2014.05.07 zhengxie bug here, should get cypher in and cypher out */
            /*if ((ret = do_encrypt(enc_ctx, text, buf))) die(ret);*/
            /*do_decrypt(dec_ctx, buf, out);*/
			if ((ret = do_decrypt(dec_ctx, text, buf))) die(ret);
			do_encrypt(enc_ctx, buf, out);
			/* end 2014.05.07 zhengxie bug here, should get cypher in and cypher out */
            break;

        case SQLUDF_FINAL_CALL:
            l->end_time = time(NULL);

			/* beg 2014.04.23 zhenxie insert log to db */
			sprintf( db_log,
                    "\"[%s] Update finished, %lu row in %ds\"\n",
                    timestamp(buf), l->row_count,
                    (int)(difftime(l->end_time, l->begin_time)));

			INSERT_DB_LOG( db_log )
			/* end 2014.04.23 zhenxie insert log to db */

            // write log if there is one
            if  (l->logfile) {

				fputs( db_log, l->logfile );
                /*fprintf(l->logfile,*/
                    /*"[%s] Encrypt finished, %lu row in %ds\n",*/
                    /*timestamp(buf), l->row_count,*/
                    /*(int)(difftime(l->end_time, l->begin_time)));*/
                fclose(l->logfile);
            }


			fputs( db_log, l->logfile );

            destroy_encrypt_context(enc_ctx);
            destroy_decrypt_context(dec_ctx);
        default: break;
    }

    return;

error:
	/* beg 2014.04.23 zhenxie insert log to db */
	sprintf( db_log,
            "\"[%s] ERROR: UPDATE fail colid: %s, Message: %s\"\n",
            timestamp(buf), colid, errmsg[errcode]);

	insert_log_db( db_log );

	/* end 2014.04.23 zhenxie insert log to db */
    if (l->logfile) {
        /*fprintf(l->logfile,*/
            /*"[%s] ERROR: UPDATE fail colid: %s, Message: %s\n",*/
            /*timestamp(buf), colid, errmsg[errcode]);*/
		fputs( db_log, l->logfile );
        fclose(l->logfile);
    }
    if (enc_ctx) destroy_encrypt_context(enc_ctx);
    if (dec_ctx) destroy_decrypt_context(dec_ctx);
    // write error mesxsages
    snprintf(SQLUDF_MSGTX, 69,
        "[NOT A BUG] %d:%d %s", errcode, line, errmsg[errcode]);
    strcpy(SQLUDF_STATE, "38900");
    return;
}

void SQL_API_FN db2_encrypt(
    SQLUDF_VARCHAR * text,
    SQLUDF_VARCHAR * colid,
    SQLUDF_VARCHAR * out,
    SQLUDF_NULLIND * text_null,
    SQLUDF_NULLIND * colid_null,
    SQLUDF_NULLIND * out_null,
    SQLUDF_TRAIL_ARGS_ALL)
{


    // For error handling
    int line = 0, errcode = 0, ret = 0;

    // restore enviroment stored in SCRATCHPAD
    struct local_t    * l   = (struct local_t *)SQLUDF_SCRAT->data;
    encrypt_context_t * ctx = l->enc_ctx;
    char buf[1024];
	char db_log[1024];

    if (*colid_null || !colid[0]) die(ERROR_NULLCOLID);

    switch (SQLUDF_CALLT)
   	{
        case SQLUDF_FIRST_CALL:
			dbglog("enter into db2_encrypt\n");
            // First call, init everything
            memset(l, 0, sizeof(struct local_t));
			/*sprintf(buf, "%s/" PREFIX "/privacyprot.log", getenv("HOME")); // linux*/
			sprintf(buf, "%s/" PREFIX "/privacyprot.log", getenv("HOME")==NULL?"C:":getenv("HOME")); // windows
            l->logfile    = fopen(buf, "a+");
            l->begin_time = time(NULL);

            // init encrypt context
            if (!(ctx = calloc(1, sizeof(encrypt_context_t))))
                    die(ERROR_NOMEM);
            if ((ret = init_encrypt_context(ctx, colid))) die(ret);
            l->enc_ctx = ctx;

			dbglog("init encrypt context done!\n");

			/* beg 2014.04.23 zhenxie insert log to db */
			sprintf( db_log,
                    "\"[%s] Starting encrypt colid: %s, "
                    "Algorithm: %s, Policy: %d, hold %d byte(s), "
                    "md5: %s, compressing: %s\"\n",
                    timestamp(buf), colid, ctx->info.algo_name, ctx->info.policy,
                    ctx->info.hold_bytes,
                    ctx->info.md5[0]? ctx->info.md5: "builtin",
                    ctx->info.type == TYPE_NUMSTRING? "yes": "no");

			INSERT_DB_LOG( db_log )
			/* end 2014.04.23 zhenxie insert log to db */


            // write log
            if (l->logfile) {
                fputs( db_log, l->logfile );
                fflush(l->logfile);
            }

        case SQLUDF_NORMAL_CALL:
            *out_null = 0;
            l->row_count++;
            if ((ret = do_encrypt(ctx, text, out))) die(ret);
            break;
        case SQLUDF_FINAL_CALL:
            l->end_time = time(NULL);

            // write log if there is one
            if  (l->logfile) {

				/* beg 2014.04.23 zhenxie insert log to db */
				sprintf( db_log,
                    "\"[%s] Encrypt finished, %lu row in %ds\"\n",
                    timestamp(buf), l->row_count,
                    (int)(difftime(l->end_time, l->begin_time)));

				INSERT_DB_LOG( db_log )
				/* end 2014.04.23 zhenxie insert log to db */

                fputs( db_log, l->logfile );
                /*fprintf(l->logfile,*/
                    /*"[%s] Encrypt finished, %lu row in %ds\n",*/
                    /*timestamp(buf), l->row_count,*/
                    /*(int)(difftime(l->end_time, l->begin_time)));*/

                fclose(l->logfile);
            }
            destroy_encrypt_context(ctx);
        default: break;
    }

    return;
error:
    if (l->logfile) {
		sprintf( db_log,
            "\"[%s] ERROR: Encrypt fail. colid: %s, Message: %s\"\n",
            timestamp(buf), colid, errmsg[errcode]);

		insert_log_db( db_log );

		fputs( db_log, l->logfile );
        /*fprintf(l->logfile,*/
            /*"[%s] ERROR: Encrypt fail. colid: %s, Message: %s\n",*/
            /*timestamp(buf), colid, errmsg[errcode]);*/
        fclose(l->logfile);
    }
    if (ctx) destroy_encrypt_context(ctx);
    // write error mesxsages
    snprintf(SQLUDF_MSGTX, 69,
        "[NOT A BUG] %d:%d %s", errcode, line, errmsg[errcode]);
    strcpy(SQLUDF_STATE, "38900");
    return;
}

void SQL_API_FN db2_decrypt(
    SQLUDF_VARCHAR * text,
    SQLUDF_VARCHAR * out,
    SQLUDF_NULLIND * text_null,
    SQLUDF_NULLIND * out_null,
    SQLUDF_TRAIL_ARGS_ALL) {

    struct local_t    * l   = (struct local_t *)(SQLUDF_SCRAT->data);
    decrypt_context_t * ctx = l->dec_ctx;

    int errcode = 0, line = 0, ret = 0;
    char buf[1024];
	char db_log[1024];

    switch (SQLUDF_CALLT) {
        case SQLUDF_FIRST_CALL:
            // First call, init everything
			dbglog("enter into db2_decrypt\n");
			/*sprintf(buf, "%s/%s/privacyprot.log", getenv("HOME"), PREFIX); // linux*/
			sprintf(buf, "%s/%s/privacyprot.log", getenv("HOME")==NULL?"C:":getenv("HOME"), PREFIX); // windows
            l->logfile    = fopen(buf, "a+");
            l->begin_time = time(NULL);

            // init decrypt context
            if (!(ctx = calloc(1, sizeof(decrypt_context_t)))) die(ERROR_NOMEM);
            if ((ret = init_decrypt_context(ctx))) die(ret);
            l->dec_ctx = ctx;
			dbglog("init decrypt context done!\n");

        case SQLUDF_NORMAL_CALL:
            // Do the encrypt
            do_decrypt(ctx, text, out);
            *out_null = 0;
            l->row_count++;
            break;
        case SQLUDF_FINAL_CALL:
            l->end_time = time(NULL);

			sprintf( db_log,
                    "\"[%s] Decrypt finished, %ld row in %ds\"\n",
                    timestamp(buf), l->row_count,
                    (int)(difftime(l->end_time, l->begin_time))
					);
			INSERT_DB_LOG( db_log )

            // write log if there is one
            if (l->logfile) {
                /*fprintf(l->logfile,*/
                    /*"[%s] Decrypt finished, %ld row in %ds\n",*/
                    /*timestamp(buf), l->row_count,*/
                    /*(int)(difftime(l->end_time, l->begin_time)));*/
				fputs( db_log, l->logfile );

                fclose(l->logfile);
            }
            destroy_decrypt_context(ctx);
        default: break;
    }

    return;

error:
    if (ctx) destroy_decrypt_context(ctx);
    // write error messages
    snprintf(SQLUDF_MSGTX, 69,
        "[NOT A BUG] %d:%d %s", line, errcode, errmsg[errcode]);
    strcpy(SQLUDF_STATE, "38900");
    return;
}

void SQL_API_FN db2_base64_decode(
    SQLUDF_VARCHAR * text,
    SQLUDF_VARCHAR * out,
    SQLUDF_NULLIND * text_null,
    SQLUDF_NULLIND * out_null,
    SQLUDF_TRAIL_ARGS_ALL) {

    struct local_t    * l   = (struct local_t *)(SQLUDF_SCRAT->data);
    decrypt_context_t * ctx = l->dec_ctx;

    int errcode = 0, line = 0, ret = 0;
    char buf[1024];
	char db_log[1024];

    switch (SQLUDF_CALLT) {
        case SQLUDF_FIRST_CALL:
            // First call, init everything
			dbglog("enter into db2_base64_decode\n");
            sprintf(buf, "%s/%s/privacyprot.log", getenv("HOME"), PREFIX);
            l->logfile    = fopen(buf, "a+");
            l->begin_time = time(NULL);

            // init decrypt context
            if (!(ctx = calloc(1, sizeof(decrypt_context_t)))) die(ERROR_NOMEM);
            if ((ret = init_decrypt_context(ctx))) die(ret);
            l->dec_ctx = ctx;
			dbglog("init decrypt context done!\n");

        case SQLUDF_NORMAL_CALL:
            // Do the encrypt
            do_base64_decode(ctx, text, out);
            *out_null = 0;
            l->row_count++;
            break;
        case SQLUDF_FINAL_CALL:
            l->end_time = time(NULL);

			sprintf( db_log,
                    "\"[%s] Decrypt finished, %ld row in %ds\"\n",
                    timestamp(buf), l->row_count,
                    (int)(difftime(l->end_time, l->begin_time))
					);
			/*INSERT_DB_LOG( db_log )*/

            // write log if there is one
            if (l->logfile) {
                /*fprintf(l->logfile,*/
                    /*"[%s] Decrypt finished, %ld row in %ds\n",*/
                    /*timestamp(buf), l->row_count,*/
                    /*(int)(difftime(l->end_time, l->begin_time)));*/
				fputs( db_log, l->logfile );

                fclose(l->logfile);
            }
            destroy_decrypt_context(ctx);
        default: break;
    }

    return;

error:
    if (ctx) destroy_decrypt_context(ctx);
    // write error messages
    snprintf(SQLUDF_MSGTX, 69,
        "[NOT A BUG] %d:%d %s", line, errcode, errmsg[errcode]);
    strcpy(SQLUDF_STATE, "38900");
    return;
}
