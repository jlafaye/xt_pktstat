CFLAGS=-O2 -Wall -I../kernel/include # -I/home/jlafaye/opt/include

lib%.so: lib%.o
	gcc  -shared -fpic -o $@ $^;

lib%.o: lib%.c
	gcc ${CFLAGS} -DPIC -fPIC -D_INIT=lib$*_init -c -o $@ $<;

all: libxt_pktstat.so

clean:
	rm -f lib*.o
	rm -f lib*.so

