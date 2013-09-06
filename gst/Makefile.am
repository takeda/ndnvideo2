AM_VALAFLAGS = @NDNVIDEO_PACKAGES@ --pkg gstreamer-base-1.0 --vapidir ../vapi --pkg ndnvideo

plugin_LTLIBRARIES = libgstndnvideo.la

libgstndnvideo_la_SOURCES = \
	ndnvideo.vala

libgstndnvideo_la_CFLAGS  = -I$(top_srcdir)/src $(GST_CFLAGS) $(GST_BASE_CFLAGS)
libgstndnvideo_la_LIBADD  = $(top_builddir)/src/libndnvideo.la $(GST_LIBS) $(GST_BASE_LIBS) $(OPENSSL_LIBS) $(CCN_LIBS)
libgstndnvideo_la_LDFLAGS = $(GST_PLUGIN_LDFLAGS) $(OPENSSL_LDFLAGS) $(CCN_LDFLAGS) -module -avoid-version
# Looks like this can't be used because libccn is only compiled statically
#libgstndnvideo_la_LIBTOOLFLAGS = --tag=disable-static

