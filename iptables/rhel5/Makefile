IPTABLES_VERSION=$(shell /usr/local/sbin/iptables --version | cut -d ' ' -f 2 | sed 's/^v//g')
CFLAGS=-Wall -DIPTABLES_VERSION=\"$(IPTABLES_VERSION)\" -I../../kernel/include # -I/home/jlafaye/opt/include


lib%.so: lib%.o
	ld  -shared -fpic -init lib$*_init -o $@ $^;

lib%.o: lib%.c
	gcc ${CFLAGS} -g -O0 -shared -DPIC -fPIC -D_INIT=lib$*_init -c -o $@ $<;

all: libipt_pktstat.so

clean:
	rm -f lib*.o
	rm -f lib*.so

