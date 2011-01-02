SHELL = /bin/sh
ETC = $(DESTDIR)/etc
SBIN = $(DESTDIR)/usr/sbin

all:
	echo "Don't panic"

pkg: debian/changelog
	dpkg-buildpackage
install:
	install -d $(SBIN) $(ETC)
	install pagekite.py $(SBIN)
	install -m644 pagekite.rc $(ETC)

mrp:
	debian/rules clean
