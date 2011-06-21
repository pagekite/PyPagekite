# Makefile for building combined pagekite.py files.

APPVER=`./pk --appver`

combined: startcom.txt pagekite tools socks.py
	@echo Version is `./pk --appver`
	@./scripts/combine.py startcom.txt socks.py \
	             pagekite/__init__.py pagekite/__main__.py \
	             >pagekite-$(APPVER).py
	@chmod +x pagekite-$(APPVER).py
	@ls -l pagekite-*.py

pagekite: pagekite/__init__.py pagekite/__main__.py

dev: socks.py

socks.py: ../PySocksipyChain/socks.py
	@ln -fs ../PySocksipyChain/socks.py socks.py

tools: scripts/combine.py Makefile

distclean: clean
	@rm -vf pagekite-0.*.py

clean:
	@rm -vf socks.py *.pyc */*.pyc
