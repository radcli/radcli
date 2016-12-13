#
#  Copyright (C) 1996,1997 Lars Fenneberg
#  Copyright (C) 2015 Nikos Mavrogiannopoulos
#
#  See the file COPYRIGHT for the respective terms and conditions.
#
#

AC_INIT([radcli], [1.2.7], [n.mavrogiannopoulos@gmail.com])

AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_TARGET([])

AC_SUBST(MAJOR_VERSION, `echo $PACKAGE_VERSION | sed 's/\(.*\)\..*\..*/\1/g'`)
AC_SUBST(MINOR_VERSION, `echo $PACKAGE_VERSION | sed 's/.*\.\(.*\)\..*/\1/g'`)
AC_SUBST(PATCH_VERSION, [[`echo $PACKAGE_VERSION | sed 's/.*\..*\.\([0-9]*\).*/\1/g'`]])
AC_SUBST(NUMBER_VERSION, `printf "0x%02x%02x%02x" $MAJOR_VERSION $MINOR_VERSION $PATCH_VERSION`)

# Library code modified:                              REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
V_CURRENT=5
V_REVISION=2
V_AGE=1
LIBVERSION="$V_CURRENT:$V_REVISION:$V_AGE"
LIBMAJOR=`expr $V_CURRENT - $V_AGE`

AC_SUBST(LIBVERSION)
AC_SUBST(LIBMAJOR)

AM_INIT_AUTOMAKE([1.11.3 -Wall -Wno-override])

pkgsysconfdir=${sysconfdir}/$PACKAGE
AC_SUBST(pkgsysconfdir)

PKG_PROG_PKG_CONFIG
LT_INIT([win32-dll,shared])

AC_PROG_CC

dnl Needed for normal compile
AC_PATH_PROG(AR, ar)
AC_PROG_LN_S

gl_LD_VERSION_SCRIPT

dnl HAVE_SHADOW_PASSWORDS
AC_MSG_CHECKING(whether to enable legacy library compatibility)
AC_ARG_ENABLE(legacy-compat,
[  --enable-legacy-compat  Enable compatibility mode with radiusclient-ng and freeradius-client],
[
        AC_MSG_RESULT(yes)
	enable_compat=yes
],
[
        AC_MSG_RESULT(no)
	enable_compat=no
]
)

AM_CONDITIONAL(ENABLE_LEGACY_COMPAT, test "$enable_compat" = "yes")


dnl Check if we need -lsocket.
AC_CHECK_LIB(socket, socket)

dnl Checks for endianness
AC_C_BIGENDIAN

dnl Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS(signal.h sys/signal.h sys/stat.h)
AC_CHECK_HEADERS(fcntl.h sys/fcntl.h)
AC_CHECK_HEADERS(sys/utsname.h getopt.h unistd.h)
AC_CHECK_HEADERS(sys/file.h termios.h sys/ioctl.h)
AC_CHECK_HEADERS(netdb.h syslog.h pwd.h)
AC_CHECK_HEADERS(sys/socket.h netinet/in.h arpa/inet.h)
if test "$shadow_passwords" = "yes"
then
	AC_CHECK_HEADER(shadow.h)
fi


dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

dnl Checks for library functions.
AC_FUNC_MEMCMP
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_FUNC_ALLOCA
AC_REPLACE_FUNCS(strdup strerror strcasecmp)
AC_CHECK_FUNCS(fcntl uname gethostname sysinfo getdomainname)
AC_CHECK_FUNCS(random rand snprintf vsnprintf strlcpy)

AC_CHECK_FUNCS([pthread_mutex_lock],,)
if test "$ac_cv_func_pthread_mutex_lock" != "yes";then
	AC_LIB_HAVE_LINKFLAGS(pthread,, [#include <pthread.h>], [pthread_mutex_lock (0);])
fi

AC_CHECK_FUNCS(clock_gettime, [], [
  AC_CHECK_LIB(rt, clock_gettime, [
    AC_DEFINE(HAVE_CLOCK_GETTIME, 1)
    REST_LIBS="$REST_LIBS -lrt"
  ])
])

if test "$ac_cv_func_uname" = 'yes' && test "$cross_compiling" = 'no'
then
	AC_MSG_CHECKING([for field domainname in struct utsname])
	AC_TRY_RUN([
	#include <sys/utsname.h>

	main(int argc, char **argv)
	{
		struct utsname uts;
		uts.domainname[0] = '\0';
	}
	],
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_STRUCT_UTSNAME_DOMAINNAME),
	AC_MSG_RESULT(no)
	)
fi

AC_MSG_CHECKING([for getentropy])
AC_LINK_IFELSE([AC_LANG_PROGRAM([
          #include <unistd.h>],[
                  getentropy(0, 0);
                 ])],
                 [AC_MSG_RESULT(yes)
                  AC_DEFINE([HAVE_GETENTROPY], 1, [Enable the OpenBSD getentropy function])
                  enable_getrandom=getentropy],
                 [AC_MSG_RESULT(no)])

AC_MSG_CHECKING([for /dev/urandom])
if test -c /dev/urandom
then
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_DEV_URANDOM)
else
	AC_MSG_RESULT(no)
fi

REQUIRES_PRIVATE="Requires.private: "

AC_ARG_WITH([tls], [AS_HELP_STRING([--without-tls],
	[enable support for DTLS @<:@default=no@:>@])],
	[with_tls=$withval],
	[with_tls=yes])

if test "$with_tls" != no; then
	PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.1.0], [use_gnutls=yes], [use_gnutls=no])

	if test "$use_gnutls" = yes;then
		CRYPTO_CFLAGS="$CRYPTO_CFLAGS $LIBGNUTLS_CFLAGS"
		CRYPTO_LIBS="$CRYPTO_LIBS $LIBGNUTLS_LIBS"
		AC_DEFINE([HAVE_GNUTLS], 1, [Define to 1 to use gnutls for TLS and DTLS.])
		REQUIRES_PRIVATE="${REQUIRES_PRIVATE} gnutls,"
	fi
fi

AM_CONDITIONAL(ENABLE_GNUTLS, test "$use_gnutls" = "yes")


PKG_CHECK_MODULES(NETTLE, [nettle >= 2.4], [use_nettle=yes])
if test "$use_nettle" = yes;then
	CRYPTO_CFLAGS="$CRYPTO_CFLAGS $NETTLE_CFLAGS"
	CRYPTO_LIBS="$CRYPTO_LIBS $NETTLE_LIBS"
	AC_DEFINE([HAVE_NETTLE], 1, [Define to 1 to use nettle for MD5.])
	REQUIRES_PRIVATE="${REQUIRES_PRIVATE} nettle"
fi

AM_CONDITIONAL(ENABLE_NETTLE, test "$use_nettle" = "yes")


LINK_LIBS="$CRYPTO_LIBS $REST_LIBS $LIBS"

AC_SUBST(CRYPTO_CFLAGS, [$CRYPTO_CFLAGS])
AC_SUBST(LINK_LIBS, [$CRYPTO_LIBS])
AC_SUBST(REQUIRES_PRIVATE)

dnl Determine PATH setting
echo $ac_n "using the following PATH setting for exec'ed programs... $ac_c" 1>&6
AC_ARG_WITH(secure-path,
[  --with-secure-path      PATH setting for exec'ed programs],
[
        AC_MSG_RESULT($withval)
        RC_SECURE_PATH=$withval
],
[
        AC_MSG_RESULT(/bin:/usr/bin:/usr/local/bin)
	RC_SECURE_PATH=/bin:/usr/bin:/usr/local/bin
]
)

dnl Checking which syslog facility to use
AC_MSG_CHECKING(which syslog facility to use)
AC_ARG_WITH(facility,
[  --with-facility         Syslog facility to use],
[
        AC_MSG_RESULT($withval)
        RC_LOG_FACILITY=$withval
],
[
        AC_MSG_RESULT(LOG_DAEMON)
        RC_LOG_FACILITY=LOG_DAEMON
]
)

AC_SUBST(RC_SECURE_PATH)
AC_SUBST(RC_LOG_FACILITY)

AH_OUTPUT([HAVE_DEV_URANDOM], [/* does /dev/urandom exist ? */
#undef HAVE_DEV_URANDOM])
AH_OUTPUT([HAVE_SHADOW_PASSWORDS], [/* shadow password support */
#undef HAVE_SHADOW_PASSWORDS])
AH_OUTPUT([HAVE_STRUCT_UTSNAME_DOMAINNAME], [/*struct utsname has domainname field */
#undef HAVE_STRUCT_UTSNAME_DOMAINNAME])
AH_OUTPUT([NEED_SIG_PROTOTYPES], [/* do you need the sig* prototypes ? */
#undef NEED_SIG_PROTOTYPES])
AH_OUTPUT([PACKAGE], [
#undef PACKAGE])
AH_OUTPUT([VERSION], [
#undef VERSION])

AC_CONFIG_HEADERS([config.h])
dnl LTLIBOBJS=`echo "$LIB@&t@OBJS" | sed 's,\.[[^.]]* ,.lo ,g;s,\.[[^.]]*$,.lo,'`
dnl AC_SUBST(LTLIBOBJS)
AC_CONFIG_FILES([
lib/radcli.pc
lib/radcli.map
Makefile
include/Makefile lib/Makefile src/Makefile man/Makefile etc/Makefile
include/radcli/version.h
doc/Makefile
doc/Doxyfile
tests/Makefile
tests/docker/Makefile
])
AC_CONFIG_COMMANDS([default],[[test -z "$CONFIG_HEADERS" || echo timestamp > stamp-h]],[[]])
AC_OUTPUT

chmod -w lib/radcli.map lib/radcli.pc

AC_MSG_NOTICE([Configuration:

  Additional libraries:      $LINK_LIBS
  Nettle for MD5:            $use_nettle
  TLS and DTLS support:      $use_gnutls
  freeradius-client compat:  $enable_compat
])
