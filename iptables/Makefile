CFLAGS=-O2 -Wall -I../kernel/include

lib%.so: lib%.o
	gcc -shared -o $@ $^;

lib%.o: lib%.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -c -o $@ $<;

all: libxt_pktstat.so

clean:
	rm -f lib*.o
	rm -f lib*.so

