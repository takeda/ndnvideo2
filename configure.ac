AC_INIT([ndnvideo], [0.0.1], [takeda@takeda.tk], [ndnvideo], [https://github.com/takeda/ndnvideo2])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_HEADERS(config.h)

AC_CONFIG_AUX_DIR([m4-aux])
AC_CONFIG_MACRO_DIR([m4-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# Required by automake 1.12, not recognized by automake 1.11
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_PROG_CC
AC_PROG_LIBTOOL
AC_DISABLE_STATIC

AC_PATH_PROG(VALAC, valac, valac)
AC_SUBST(VALAC)

AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

VALAFLAGS="--pkg gstreamer-base-1.0 --enable-experimental"
AC_SUBST(VALAFLAGS)

# Checks for libraries.
AX_CHECK_CCN([], AC_MSG_ERROR([CCNx is required to compile ndnvideo]))

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

AC_CONFIG_FILES([
	Makefile
	gst/Makefile
	])

AC_OUTPUT
