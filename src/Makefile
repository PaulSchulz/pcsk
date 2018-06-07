# for debug purposes
CFLAGS += -g -O0

binary: pcsk

clean:
	rm -f pcsk *.o

install: binary
	$(INSTALL) pcsk $(DESTDIR)/bin/

pcsk: pcsk.c
	$(CC) $(CFLAGS) -o pcsk pcsk.c

.PHONY: binary clean install
