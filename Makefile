BINDIR := $(PREFIX)/lib/pocketcrypt
INCDIR := $(PREFIX)/include/pocketcrypt
LIBDIR := $(PREFIX)/lib

CFLAGS := -march=native -O3 -Wall -Wfatal-errors
override CFLAGS += -I.

%:: %.c Makefile
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

test: $(basename $(wildcard test/*.c))
	@echo $(foreach TEST,$^,&& $(TEST))

test/x25519-known test/x25519-sanity test/x25519-speed: x25519.[ch]
test/duplex-known test/duplex-sanity test/duplex-speed: duplex.h
test/gimli-known test/gimli-sanity test/gimli-speed: duplex.h

tools: $(basename $(wildcard tools/*.c))

tools/cloak tools/reveal: duplex.h swirl.h
tools/decrypt tools/encrypt tools/sign tools/verify: duplex.h x25519.[ch]
tools/keymerge tools/keysplit: shamir.[ch]
tools/keypair: x25519.[ch]

libpocketcrypt.so: shamir.c x25519.c Makefile
	$(CC) $(CFLAGS) -fpic -shared -o $@ $(filter %.c,$^)

libpocketcrypt.a: shamir.c x25519.c Makefile
	$(CC) $(CFLAGS) -c $(filter %.c,$^)
	$(AR) rcs $@ $(patsubst %.c,%.o,$(filter %.c,$^))

install-headers:
	mkdir -p $(DESTDIR)$(INCDIR) $(DESTDIR)$(LIBDIR)
	install -m 0644 $(wildcard *.h) $(DESTDIR)$(INCDIR)

install-shared: install-headers libpocketcrypt.so
	install -m 0644 libpocketcrypt.so $(DESTDIR)$(LIBDIR)

install-static: install-headers libpocketcrypt.a
	install -m 0644 libpocketcrypt.a $(DESTDIR)$(LIBDIR)

install-tools: $(basename $(wildcard tools/*.c))
	mkdir -p $(DESTDIR)$(BINDIR)
	install -s $^ $(DESTDIR)$(BINDIR)

clean:
	rm -f $(basename $(wildcard test/*.c tools/*.c)) *.a *.o *.so

.PHONY: clean install-* test tools
