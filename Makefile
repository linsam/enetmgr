CFLAGS:=-g

all: test

test: test.c
	gcc -o test -I /usr/include/libnl3 test.c -lnl-3 -lnl-route-3
