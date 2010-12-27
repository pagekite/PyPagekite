SHELL = /bin/sh
ETC = $(DESTDIR)/etc
SBIN = $(DESTDIR)/usr/sbin

all:
	echo "Relax"

install:
	install -d $(SBIN) $(ETC)
	install pagekite.py $(SBIN)
	install -m644 pagekite.rc $(ETC)
