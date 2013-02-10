#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([src/pycrypto_compat.h])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC

# Checks for compiler flags.
old_CFLAGS="$CFLAGS"
CFLAGS=-maes
AC_MSG_CHECKING([whether CC supports -maes])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])], [
  AC_MSG_RESULT([yes])
  AC_DEFINE(HAVE_MAES, [1], [Define if CC supports -maes])
  have_maes=yes
  ], [AC_MSG_RESULT([no])]
)
CFLAGS="$old_cflags"

# Checks for libraries.
AC_ARG_WITH([gmp], AS_HELP_STRING([--without-gmp], [Build without gmp library (default: test)]))
AS_IF([test "x$with_gmp" != "xno"], [
  AC_CHECK_LIB([gmp], [__gmpz_init])
])

AC_ARG_WITH([mpir], AS_HELP_STRING([--without-mpir], [Build without mpir library (default: test)]))
AS_IF([test "x$with_mpir" != "xno"], [
  AC_CHECK_LIB([mpir], [__gmpz_init])
])

AC_CHECK_DECLS([mpz_powm], [], [], [
[#if HAVE_LIBGMP
# include <gmp.h>
#elif HAVE_LIBMPIR
# include <mpir.h>
#endif
]])
AC_CHECK_DECLS([mpz_powm_sec], [], [], [
[#if HAVE_LIBGMP
# include <gmp.h>
#elif HAVE_LIBMPIR
# include <mpir.h>
#endif
]])

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h limits.h stddef.h stdint.h stdlib.h string.h wchar.h cpuid.h])
old_CPPFLAGS="$CPPFLAGS"
AS_IF([test "x$have_maes" = "xyes"], [
    CPPFLAGS="$CPPFLAGS -maes"
])
AC_CHECK_HEADERS([wmmintrin.h])
CPPFLAGS="$old_CPPFLAGS"

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memmove memset])

AC_OUTPUT
