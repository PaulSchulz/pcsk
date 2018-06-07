INSTALL = install
export INSTALL

DESTDIR ?= /usr/local
export DESTDIR

DIRS = src lib doc

binary:
	for i in $(DIRS); do \
		$(MAKE) -C $$i binary; \
	done

clean:
	for i in $(DIRS); do \
		$(MAKE) -C $$i clean; \
	done

install: binary
	for i in $(DIRS); do \
		$(MAKE) -C $$i install; \
	done

.PHONY: binary clean install
