all: rjserver_mipsel

rjserver: rjserver.c
	gcc -Wall -O0 -g -o rjserver rjserver.c -lpcap

rjserver_mipsel: rjserver.c
	mipsel-linux-gcc -I/usr/include -Wall -Os -o rjserver_mipsel rjserver.c ./libpcap.so.0.9.8
	mipsel-linux-strip rjserver_mipsel

rjserver.c: ~/rjserver.c
	cp -v ~/rjserver.c rjserver.c
