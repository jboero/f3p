NAME     = f3p
VERSION  = 0.1.0
PREFIX  ?= /usr
BINDIR   = $(PREFIX)/bin
LIBDIR   = $(PREFIX)/lib/$(NAME)
DOCDIR   = $(PREFIX)/share/doc/$(NAME)
UDEVDIR  = $(PREFIX)/lib/udev/rules.d
APPDIR   = $(PREFIX)/share/applications

.PHONY: all install uninstall clean dist srpm rpm check

all:
	@echo "Targets: check, install, uninstall, dist, srpm, rpm, clean"

check:
	python3 -c "import ast; ast.parse(open('f3p/f3p.py').read())"
	python3 -c "import ast; ast.parse(open('f3p/f3p_gui.py').read())"
	python3 f3p/f3p.py --help > /dev/null
	python3 f3p/f3p.py scan --help > /dev/null
	python3 f3p/f3p.py doctor --help > /dev/null
	python3 f3p/f3p.py gui --help > /dev/null
	@echo "OK"

install:
	install -d $(DESTDIR)$(LIBDIR)
	install -m 0755 f3p/f3p.py $(DESTDIR)$(LIBDIR)/f3p.py
	install -m 0644 f3p/f3p_gui.py $(DESTDIR)$(LIBDIR)/f3p_gui.py
	install -d $(DESTDIR)$(BINDIR)
	ln -sf $(LIBDIR)/f3p.py $(DESTDIR)$(BINDIR)/$(NAME)
	install -d $(DESTDIR)$(DOCDIR)
	install -m 0644 README.md LICENSE $(DESTDIR)$(DOCDIR)/
	install -d $(DESTDIR)$(DOCDIR)/case-studies
	install -m 0644 docs/case-studies/luna-t10-wwt26ultra.md $(DESTDIR)$(DOCDIR)/case-studies/
	install -d $(DESTDIR)$(UDEVDIR)
	install -m 0644 contrib/51-android.rules $(DESTDIR)$(UDEVDIR)/51-android.rules
	install -d $(DESTDIR)$(APPDIR)
	install -m 0644 contrib/f3p.desktop $(DESTDIR)$(APPDIR)/f3p.desktop

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(NAME)
	rm -rf $(DESTDIR)$(LIBDIR)
	rm -rf $(DESTDIR)$(DOCDIR)
	rm -f $(DESTDIR)$(UDEVDIR)/51-android.rules
	rm -f $(DESTDIR)$(APPDIR)/f3p.desktop

dist:
	tar --transform 's,^,$(NAME)-$(VERSION)/,' \
	    -czf $(NAME)-$(VERSION).tar.gz \
	    f3p/ contrib/ rpm/ docs/ \
	    Makefile README.md LICENSE

srpm: dist
	rpmbuild -bs rpm/$(NAME).spec \
	    --define "_sourcedir $(PWD)" \
	    --define "_srcrpmdir $(PWD)"

rpm: dist
	rpmbuild -ba rpm/$(NAME).spec \
	    --define "_sourcedir $(PWD)" \
	    --define "_rpmdir $(PWD)" \
	    --define "_srcrpmdir $(PWD)"

clean:
	rm -f *.tar.gz *.src.rpm
	rm -rf noarch/ x86_64/ aarch64/
	find . -name __pycache__ -type d -exec rm -rf {} +
