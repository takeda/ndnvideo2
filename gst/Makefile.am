AM_CPPFLAGS = $(GST_CFLAGS)

plugin_LTLIBRARIES = libgstndnvideo.la

libgstndnvideo_la_VALASOURCES = \
	elementbase.vala \
	ndnvideo.vala \
	publisher.vala

libgstndnvideo_la_SOURCES = \
	$(libgstndnvideo_la_VALASOURCES:.vala=.c)

libgstndnvideo_la_CFLAGS = -I$(top_srcdir)/vapi $(GST_CFLAGS) $(GST_BASE_CFLAGS)
libgstndnvideo_la_LIBADD = $(GST_LIBS) $(GST_BASE_LIBS) $(OPENSSL_LIBS) $(CCN_LIBS)
libgstndnvideo_la_LDFLAGS = $(GST_PLUGIN_LDFLAGS) $(OPENSSL_LDFLAGS) $(CCN_LDFLAGS) -module -avoid-version
# Looks like this can't be used because libccn is only compiled statically
#libgstndnvideo_la_LIBTOOLFLAGS = --tag=disable-static

EXTRA_DIST = \
	$(libgstndnvideo_la_VALASOURCES)

SUFFIXES = .vala.c

.vala.c:
	$(VALAC) -C $(VALAFLAGS) --vapidir=$(top_srcdir)/vapi --pkg=ccnx $<
