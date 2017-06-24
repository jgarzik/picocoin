
if HAVE_DOXYGEN
Doxyfile.stamp:
	$(DOXYGEN) Doxyfile
	echo Timestamp > Doxyfile.stamp

CLEANFILES = Doxyfile.stamp

all-local: Doxyfile.stamp
endif

