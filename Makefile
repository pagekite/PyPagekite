# Makefile for building combined pagekite.py files.
export PYTHONPATH := .

BREED_PAGEKITE = $(shell python3 -c 'import six; print(six.__file__.replace(".pyc", ".py"))') \
                 pagekite/__init__.py \
	         pagekite/common.py \
	         pagekite/compat.py \
	         pagekite/logging.py \
	         pagekite/manual.py \
	         pagekite/proto/__init__.py \
	         pagekite/proto/ws_abnf.py \
	         pagekite/proto/proto.py \
	         pagekite/proto/parsers.py \
	         pagekite/proto/selectables.py \
	         pagekite/proto/filters.py \
	         pagekite/proto/conns.py \
	         pagekite/ui/__init__.py \
	         pagekite/ui/nullui.py \
	         pagekite/ui/basic.py \
	         pagekite/ui/remote.py \
	         pagekite/yamond.py \
	         pagekite/httpd.py \
	         pagekite/pk.py \


combined: pagekite tools doc/MANPAGE.md dev .header defaults.cfg
	@./scripts/breeder.py --compress --header .header \
	             defaults.cfg sockschain $(BREED_PAGEKITE) \
	             pagekite/__main__.py \
	             >pagekite-tmp.py
	@chmod +x pagekite-tmp.py
	@./scripts/blackbox-test.sh ./pagekite-tmp.py - \
	        && ./scripts/blackbox-test.sh ./pagekite-tmp.py - --nopyopenssl \
	        && ./scripts/blackbox-test.sh ./pagekite-tmp.py - --nossl \
	        && ./scripts/blackbox-test.sh ./pagekite-tmp.py - --tls_legacy
	@killall pagekite-tmp.py || true
	@mv pagekite-tmp.py dist/pagekite-`python3 setup.py --version`.py
	@ls -l dist/pagekite-*.py

untested: pagekite tools doc/MANPAGE.md dev .header defaults.cfg
	@./scripts/breeder.py --compress --header .header \
	             defaults.cfg sockschain $(BREED_PAGEKITE) \
	             pagekite/__main__.py \
	             >pagekite-tmp.py
	@chmod +x pagekite-tmp.py
	@mv pagekite-tmp.py dist/pagekite-`python3 setup.py --version`.py
	@ls -l dist/pagekite-*.py

doc/MANPAGE.md: pagekite pagekite/manual.py
	@python3 -m pagekite.manual --nopy --markdown >doc/MANPAGE.md

doc/pagekite.1: pagekite pagekite/manual.py
	@python3 -m pagekite.manual --nopy --man >doc/pagekite.1

dist: combined .deb

alldeb: .deb

VERSION=`python3 setup.py --version`
DEB_VERSION=`head -n1 debian/changelog | sed -e "s+.*(\(.*\)).*+\1+"`
.debprep:
	@ln -sf deb debian
	if [ "x$(VERSION)" != "x$(DEB_VERSION)" ] ; \
	then \
	  dch --maintmaint --newversion $(VERSION) --urgency=low \
              --distribution=unstable "New release." ; \
	fi

.targz:
	@python3 setup.py sdist

.deb: .debprep
	@debuild -i -us -uc
	@mv ../pagekite_*.deb dist/

.header: pagekite doc/header.txt
	@sed -e "s/@VERSION@/$(VERSION)/g" \
		< doc/header.txt >.header

test: dev
	@./scripts/blackbox-test.sh ./pk -
	@./scripts/blackbox-test.sh ./pk - --nopyopenssl
	@./scripts/blackbox-test.sh ./pk - --nossl
	@./scripts/blackbox-test.sh ./pk - --tls_legacy
	@(for pkb in scripts/legacy-testing/*py; do \
             ./scripts/blackbox-test.sh $$pkb ./pk --nossl && \
             ./scripts/blackbox-test.sh $$pkb ./pk || \
             ./scripts/blackbox-test.sh $$pkb ./pk --tls_legacy \
          ;done)

pagekite: pagekite/__init__.py pagekite/httpd.py pagekite/__main__.py

dev: sockschain
	@rm -f .SELF
	@ln -fs . .SELF
	@echo export PYTHONPATH=`pwd`
	@echo export HTTP_PROXY=
	@echo export http_proxy=

sockschain:
	@ln -fs ../PySocksipyChain/sockschain .

tools: scripts/breeder.py Makefile

scripts/breeder.py:
	@ln -fs ../../PyBreeder/breeder.py scripts/breeder.py

distclean: clean
	@rm -rvf dist/*.*

clean:
	[ -e debian ] && debuild clean || true
	@rm -vf sockschain *.py[co] */*.py[co] */*/*.py[co] scripts/breeder.py .SELF
	@rm -vf .appver pagekite-tmp.py MANIFEST setup.cfg
	@rm -vrf debian *.egg-info .header doc/pagekite.1 build/

