prefix=/usr/local
LIBDIR=$(DESTDIR)$(prefix)/lib
BINDIR=$(DESTDIR)$(prefix)/bin
DATADIR=$(DESTDIR)$(prefix)/share
LOCALEDIR=$(DATADIR)/locale
MANDIR=$(DATADIR)/man
INSTALL=install

all:
	cd src/xmpppy-0.5.0rc1 && pwd && python setup.py build && cp -r xmpp ..

clean:	Makefile

install:all
	$(INSTALL) -d $(LOCALEDIR) $(BINDIR) $(DATADIR)/poezio $(DATADIR)/poezio/data $(DATADIR)/poezio/src $(DATADIR)/poezio/src/xmpp

	$(INSTALL) -m644 data/* $(DATADIR)/poezio/data/

	for sourcefile in `find src/ -maxdepth 1 -type f | grep -v '.svn' | grep -v '.pyc'` ; do \
		$(INSTALL) -m644 $$sourcefile $(DATADIR)/poezio/src; \
	done
	$(INSTALL) -m644 src/xmpp/* $(DATADIR)/poezio/src/xmpp/

	echo "#!/usr/bin/env sh" > $(BINDIR)/poezio
	echo "cd $(DATADIR)/poezio/src/ && python poezio.py" >> $(BINDIR)/poezio
	chmod 755 $(BINDIR)/poezio

	for localename in `find locale/ -maxdepth 1 -type d | grep -v '.svn' | sed 's:locale/::g'` ; do \
		if [ -d locale/$$localename ]; then \
		    $(INSTALL) -d $(LOCALEDIR)/$$localename; \
		    $(INSTALL) -d $(LOCALEDIR)/$$localename/LC_MESSAGES; \
			msgfmt locale/$$localename/LC_MESSAGES/poezio.po -o locale/$$localename/LC_MESSAGES/poezio.mo -v; \
			$(INSTALL) -m644 locale/$$localename/LC_MESSAGES/poezio.mo $(LOCALEDIR)/$$localename/LC_MESSAGES; \
		fi \
	done

uninstall:
	rm -f $(BINDIR)/poezio
	rm -rf $(DATADIR)/poezio

	for gettextfile in `find $(LOCALEDIR) -name 'poezio.mo'` ; do \
		rm -f $$gettextfile; \
	done

mo:
	for localename in `find locale/ -maxdepth 1 -type d | grep -v '.svn' | sed 's:locale/::g'` ; do \
		if [ -d locale/$$localename ]; then \
			msgfmt locale/$$localename/LC_MESSAGES/poezio.po -o locale/$$localename/LC_MESSAGES/poezio.mo -v; \
		fi \
	done

pot:
	xgettext src/*.py --from-code=utf-8 --keyword=_ -o locale/poezio.pot
