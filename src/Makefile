all: promstest

promstest: promstest.c
	$(CC) -o $@ promstest.c

clean: 
	rm -rf promstest

install:
	install -d $(bindir)
	install -m 0755 promstest $(bindir)

uninstall:
	rm ${bindir}/promstest

.PHONY: all clean install uninstall