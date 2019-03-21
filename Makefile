prefix = /usr/local

exec_prefix = ${prefix}

bindir = ${exec_prefix}/bin

export prefix

export exec_prefix

export bindir

all clean install uninstall:
	cd src && $(MAKE) $@

.PHONY: all clean install uninstall