include ../compiler.mk
include ../Makefile.in

objects_dbutils := dbutils.o utils.o error.o
objects_db2  := db2.o utils.o error.o crypto.o
objects_jni  := jni.o utils.o error.o crypto.o
objects_ora  := oracle.o utils.o error.o crypto.o

#CFLAGS += -Werror #-DNO_LIBDL #-DNO_DEBUG
#linux
#CFLAGS += -Wall #-DNO_LIBDL #-DNO_DEBUG
#windows
CFLAGS += -Wall -DNO_LIBDL -D__int64=uint64_t -DNO_DEBUG


.PHONY: all clean core db2 jni oracle

all: $(DBTYPE) jni pputil

db2: privacy_db2.so
#linux
jni: privacy_jni.so
#windows
#jni: privacy_jni.dll

oracle: privacy_ora.so

pputil: $(objects_dbutils)
	$(CC) $(LDFLAGS) $(DB_LDFLAGS) $(objects_dbutils) -o $@

privacy_ora.so: $(objects_ora)
	$(CC) $(SHARED) $(DB_LDFLAGS) $(LDFLAGS) $(objects_ora) $(OPENSSL_LIB) -o $@

privacy_db2.so: $(objects_db2)
	$(CC) $(SHARED) $(DB_LDFLAGS) $(LDFLAGS) $(objects_db2) $(OPENSSL_LIB) -o $@

#linux
privacy_jni.so: $(objects_jni)
#windows
#privacy_jni.dll: $(objects_jni)
	$(CC) $(SHARED) $(LDFLAGS) $(objects_jni) $(PIC) $(OPENSSL_LIB) -o $@

%.o: %.c
	$(CC) $(PIC) $(CFLAGS) $(DB_CFLAGS) -c $< -o $@

crypto.o: crypto_impl.c

db2utils.c: db2utils.sqc
	$(DB2_CLI) connect to $(DATABASE) user $(USERNAME) using $(PASSWORD)
	$(DB2_CLI) prep $< PACKAGE USING pp${RNUM}
	$(DB2_CLI) connect reset

db2.c oracle.c: crypto.h utils.h error.h
db2utils.sqc: utils.h error.h
utils.c: utils.h error.h
crypto.c: utils.h error.h crypto.h crypto_impl.c
jni.c: jni.h crypto.h utils.h error.h

dbutils.o: $(DBTYPE)utils.c
	$(CC) $(PIC) $< $(CFLAGS) $(DB_CFLAGS) -c -o $@

clean:
	rm -f db2utils.c $(objects_dbutils)
	rm -f $(objects_db2) $(objects_jni) *.so pputil
	rm -f $(objects_ora) *.so pputil
	rm -f test*.c a.out *.bnd
