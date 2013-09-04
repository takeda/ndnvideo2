AC_INIT([ndnvideo], [0.0.1], [takeda@takeda.tk], [ndnvideo], [https://github.com/takeda/ndnvideo2])
AC_CONFIG_SRCDIR([gst/ndnvideo.vala])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_AUX_DIR([m4-aux])
AC_CONFIG_MACRO_DIR([m4-aux])

dnl AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_INIT_AUTOMAKE([foreign -Wall])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Required by automake 1.12, not recognized by automake 1.11
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
dnl AC_PROG_CC_STDC
AC_PROG_LIBTOOL
AC_DISABLE_STATIC

AM_PROG_VALAC([0.20.1])

AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

dnl VALAFLAGS="--pkg gstreamer-base-1.0 --enable-experimental"
dnl AC_SUBST(VALAFLAGS)

PKG_CHECK_MODULES(GOBJECT, [gobject-2.0])
AC_SUBST(GOBJECT_CFLAGS)
AC_SUBST(GOBJECT_LDFLAGS)
AC_SUBST(GOBJECT_LIBS)

NDNVIDEO_PACKAGES="--pkg gstreamer-base-1.0 --enable-experimental"
AC_SUBST(NDNVIDEO_PACKAGES)

PKG_CHECK_MODULES(GST, [gstreamer-1.0 gstreamer-base-1.0])
AC_SUBST(GST_CFLAGS)
AC_SUBST(GST_LIBS)

dnl set the plugindir where plugins should be installed (for gst/Makefile.am)
if test "x${prefix}" = "x$HOME"; then
	plugindir="$HOME/.gstreamer-1.0/plugins"
else
	plugindir="\$(libdir)/gstreamer-1.0"
fi
AC_SUBST(plugindir)

# Checks for libraries.
AX_CHECK_CCN([], AC_MSG_ERROR([CCNx is required to compile ndnvideo]))

AC_CONFIG_FILES([
	Makefile
	gst/Makefile
	src/Makefile
	test/Makefile
	vapi/Makefile
	])

AC_OUTPUT
