CFLAGS:=-g

all: enetmgr

enetmgr: enetmgr.c
	gcc -o $@ -I /usr/include/libnl3 $^ -lnl-3 -lnl-route-3
