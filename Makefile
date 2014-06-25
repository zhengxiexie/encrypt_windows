include compiler.mk
include Makefile.in

.PHONY: all src clean cfg show crypto

all: show crypto src dist

crypto: libcrypto.a
libcrypto.a: openssl-1.0.1f.tar.gz
	( \
        tar xvf $< ; \
        cd openssl-1.0.1f ; \
        ./config no-idea no-camellia no-seed no-bf no-cast no-rc2 no-md2 no-md4 \
        no-ripemd no-mdc2 no-rsa no-dsa no-dh no-ec no-ecdsa no-ecdh no-sock \
        no-ssl2 no-ssl3 no-err no-krb5 no-engine no-hw enable-aes enable-rc5 \
        enable-des enable-rc4 enable-shared -fPIC; \
        make depend ; \
        make build_crypto ; \
        cp $@ .. ; \
    )

jni: show
	+cd src && $(MAKE) jni
	#linux
	#cp src/privacy_jni.so dist
	#windows
	cp src/privacy_jni.dll dist

src:
	mkdir -p dist
	+cd src && $(MAKE) $(DBTYPE)
	#linux
	#cp src/*.so dist
	#windows
	cp src/*.dll dist

clean:
	+cd src && $(MAKE) clean
	rm -f dist/*
	#rm -f libcrypto.a

cfg:
	@(                                         \
		echo "# This file is auto generated" ; \
		echo "# DO NOT EDIT IT MANUALLY "    ; \
		echo                                 ; \
		echo "database \"$(DATABASE)\""      ; \
		echo "username \"$(USERNAME)\""      ; \
		echo "password \"$(PASSWORD)\""      ; \
		echo "schema   \"$(SCHEMA)\""        ; \
	) > $(shell basename $(CFG_FILE))
	@echo "Config file: $(shell basename $(CFG_FILE))"
	@cat  $(shell basename $(CFG_FILE))
	@cp $(shell basename $(CFG_FILE)) dist

show:
	@( \
		echo                                                    ; \
		echo "===== Current time:" $(shell date) " ====="       ; \
		echo "prefix     = $(prefix)"                           ; \
		echo "CFLAGS     = $(CFLAGS) $(PIC)"                    ; \
		echo "LDFLAGS    = $(LDFLAGS) $(SHARED)"                ; \
		echo "DB_CFLAGS  = $(DB_CFLAGS)"                        ; \
		echo "DB_LDFLAGS = $(DB_LDFLAGS)"                       ; \
		echo "CC         = $(CC)"                               ; \
		echo "LD         = $(LD)"                               ; \
		echo "DBTYPE     = $(DBTYPE)"                           ; \
	) | tee -a make-config.log
