RNUM = $(shell echo $$RANDOM)
LD_LIBRARY_PATH :=

# DB2
DB_CFLAGS  = -I $(DB2PATH)/include -D_DB2=1
DB_LDFLAGS = -L $(DB2PATH)/lib64 -lpthread

# JNI 设置
JNI_CLASSNAME = com.asiainfo.biframe.privacyprotection.util.DecryptContext
JNI_CFLAGS  = -I $(JAVA_HOME)/include -I $(JAVA_HOME)/include/$(OS)
JNI_LDFLAGS =
JAVAH = $(JAVA_HOME)/bin/javah -classpath $(CLASS_PATH)

# openssl
# linux
#OPENSSL_LIB += ../libcrypto.a
# windows
OPENSSL_LIB += ../libcrypto.dll

CFLAGS      += -I ../openssl-1.0.1f/include

CFLAGS  += $(JNI_CFLAGS)
LDFLAGS += $(JNI_LDFLAGS)

CFLAGS += -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/$(OS)
CFLAGS += -D_PREFIX="$(prefix)"

DBTYPE = db2

# ====================
# | 需要修改以下配置 |
# ====================

# 操作系统
# linux
#OS = linux
# windows
OS = win32
# OS = aix

# JAVA_HOME
#linux
#JAVA_HOME  = /usr/java/default
#windows
JAVA_HOME  = D:\PPBuild\jdk1.6.0_22
# $(JNI_CLASSNAME) 所在路径
CLASS_PATH = $(CLASSPATH):../lib:./lib

# DB2 有关
# DB2安装录经, 通常在/opt/ibm下
#linux
#DB2PATH := /opt/ibm/db2/V9.5
#windows
DB2PATH := D:\PPBuild\DB2

# pputil, 日志目录
prefix  = privacy

# db2命令, 可能在2个地方: $(DB2PATH)/bin下或者(Local Database Directory)/bin下
DB2_CLI := $(DB2PATH)/bin/db2

# 数据库配置
DATABASE = pp
USERNAME = pp
PASSWORD = pp
SCHEMA   = pp

CFG_FILE = ./cfg_file
