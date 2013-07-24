AM_VALAFLAGS = --vapidir=../vapi --pkg ndnvideo

#lib_LTLIBRARIES = libndnvideo.la
#
#libndnvideo_la_SOURCES = \
#	ccnx.c \
#	packet_generator.c \
#	repo_publisher.c

bin_PROGRAMS = testC testVala

testC_SOURCES = \
	test-C.c

testC_CFLAGS = -I$(top_srcdir)/src
testC_LDFLAGS = @OPENSSL_LDFLAGS@ @CCN_LDFLAGS@
testC_LDADD = ../src/libndnvideo.la -lm @OPENSSL_LIBS@ @CCN_LIBS@

testVala_SOURCES = \
	test-Vala.vala
#	ccnx.c \
#	repo_publisher.c \
#	packet_generator.c

testVala_CFLAGS = -I$(top_srcdir)/src @GOBJECT_CFLAGS@
testVala_LDFLAGS = @OPENSSL_LDFLAGS@ @CCN_LDFLAGS@ @GOBJECT_LDFLAGS@
testVala_LDADD = ../src/libndnvideo.la -lm @OPENSSL_LIBS@ @CCN_LIBS@ @GOBJECT_LIBS@

#myprog_SOURCES = \
#	ccnx_helper.vala \
#	test.vala

#myprog_CFLAGS = -I$(top_srcdir)/vapi @GLIB_CFLAGS@

#libgstndnvideo_la_CFLAGS = -I$(top_srcdir)/vapi $(GST_CFLAGS) $(GST_BASE_CFLAGS)
#libgstndnvideo_la_LIBADD = $(GST_LIBS) $(GST_BASE_LIBS) $(OPENSSL_LIBS) $(CCN_LIBS)
#libgstndnvideo_la_LDFLAGS = $(GST_PLUGIN_LDFLAGS) $(OPENSSL_LDFLAGS) $(CCN_LDFLAGS) -module -avoid-version
## Looks like this can't be used because libccn is only compiled statically
##libgstndnvideo_la_LIBTOOLFLAGS = --tag=disable-static

#EXTRA_DIST = \
#	$(libgstndnvideo_la_VALASOURCES)

#SUFFIXES = .vala.c
#
#.vala.c:
#	$(VALAC) -C $(VALAFLAGS) --vapidir=$(top_srcdir)/vapi --pkg=ccnx $<
