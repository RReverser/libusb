AM_CPPFLAGS = -I$(top_srcdir)/libusb
LDADD = ../libusb/libusb-1.0.la
LIBS =

stress_SOURCES = stress.c testlib.c
stress_mt_SOURCES = stress_mt.c
set_option_SOURCES = set_option.c testlib.c
init_context_SOURCES = init_context.c testlib.c

noinst_HEADERS = libusb_testlib.h
noinst_PROGRAMS = stress stress_mt set_option init_context

if BUILD_UMOCKDEV_TEST
# NOTE: We add libumockdev-preload.so so that we can run tests in-process
#       We also use -Wl,-lxxx as the compiler doesn't need it and libtool
#       would reorder the flags otherwise.
libumockdev_server_la_CPPFLAGS = ${AM_CPPFLAGS} ${UMOCKDEV_CFLAGS}
libumockdev_server_la_LIBADD = -lumockdev-preload ${UMOCKDEV_LIBS}
libumockdev_server_la_SOURCES = umockdev-server.c

noinst_LTLIBRARIES = libumockdev_server.la

umockdev_SOURCES = umockdev.cpp testlib.c
umockdev_CXXFLAGS = -std=c++17
umockdev_LDADD = ${LDADD} libumockdev_server.la

noinst_PROGRAMS += umockdev
endif
