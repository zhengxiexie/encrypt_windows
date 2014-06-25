MAKE    = make

# gcc配置(linux)
#CC      = gcc
#CFLAGS  = -O2  -D_REENTREANT -Wall
#LDFLAGS = -ldl  -Wall
#PIC     = -fPIC
#SHARED  = -shared

# gcc配置(windows)
CC      = gcc
CFLAGS  = -O2 -m32 -D_REENTREANT -Wall -DNO_LIBDL -Wl,--add-stdcall-alias -shared -D__int64="long long"
LDFLAGS = -m32 -Wall -Wl,--add-stdcall-alias -shared -D__int64="long long"
SHARED  = -shared


# Solaris suncc 配置
# CC      = cc
# CFLAGS  = -xO3 -g -native -mt -D_REENTRANT -xarch=native64
# LDFLAGS = -ldl -native -mt -xarch=native64
# PIC     = -Kpic
# SHARED  = -G

# HP-UX acc 配置
# CC      = cc
# CFLAGS  = +O2 +DD64 -D_REENTRANT
# LDFLAGS = -ldl -lc +DD64
# PIC     = +Z
# SHARED  = -Wl,-b

# xlc 配置
#CC      = xlc
#CFLAGS  = -O2 -g -q64 -D_REENTRANT
#LDFLAGS = -ldl -q64
#PIC     =
#SHARED  = -qmkshrobj
