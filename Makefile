# Makefile for building combined pagekite.py files.

pagekite-0.4.py: certs.txt pagekite tools socks.py
	./scripts/combine.py certs.txt socks.py \
	             pagekite/__init__.py pagekite/__main__.py \
	             >pagekite-0.4.py
	chmod +x pagekite-0.4.py

pagekite: pagekite/__init__.py pagekite/__main__.py

socks.py: ../PySocksipyChain/socks.py
	ln -fs ../PySocksipyChain/socks.py socks.py

tools: scripts/combine.py Makefile

clean:
	rm -f pagekite-0.4.py socks.py *.pyc */*.pyc
