
##
## Toplevel Makefile.am
##

ACLOCAL_AMFLAGS = -I m4

SUBDIRS		= m4 external doc include lib src test

EXTRA_DIST	= autogen.sh TODO

pkg-deb: dist
	- rm -rf $(distdir)
	mkdir -p $(distdir)
	mv $(distdir).tar.gz $(distdir)/$(PACKAGE)_$(VERSION).orig.tar.gz

	tar --directory $(distdir)/ \
		-xf $(distdir)/$(PACKAGE)_$(VERSION).orig.tar.gz

	cp -r $(top_srcdir)/contrib/debian $(distdir)/$(PACKAGE)-$(VERSION)/
	cd $(distdir)/$(PACKAGE)-$(VERSION)/; \
		./configure; \
		dpkg-buildpackage -us -uc -rfakeroot; \
		mv ../*.deb ../../

	$(am__post_remove_distdir)
