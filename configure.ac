AC_INIT([Crypto-Tools], [1.0], [remyknight1119@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_ARG_WITH(openssl_libraries,
			[  --with-openssl-libraries=DIR   openssl library directory],
			[with_openssl_libraries="$withval"],
			[with_openssl_libraries=no])

AC_ARG_WITH(pcap_libraries,
			[  --with-pcap-libraries=DIR   pcap library directory],
			[with_pcap_libraries="$withval"],
			[with_pcap_libraries=no])

CPPFLAGS="${CPPFLAGS} -I/usr/local/include"
LIBS="${LIBS} -L/usr/local/lib"

LIBCRYPTO=""
AC_CHECK_HEADERS([openssl/ssl.h], , LIBCRYPTO="no")

if test "$LIBCRYPTO" = "no"; then
    echo
    echo "   ERROR!  libcrypto headers not found, go get it from"
    echo "   http://www.xmlsoft.org/downloads.html"
    echo "   or use the --with-libcrypto-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LIBPCAP=""
AC_CHECK_HEADERS([pcap/pcap.h], , LIBPCAP="no")

if test "$LIBPCAP" = "no"; then
    echo
    echo "   ERROR!  libpcap headers not found, go get it from"
    echo "   http://www.xmlsoft.org/downloads.html"
    echo "   or use the --with-libpcap-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LLIBCRYPTO=""
AC_CHECK_LIB([crypto], [ASN1_generate_v3], , LLIBCRYPTO="no")

if test "$LLIBCRYPTO" = "no"; then
    echo
    echo "   ERROR!  libdv_crypto library not found, go get it from"
    echo "   or use the --with-libdv_crypto-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LLIBSSL=""
AC_CHECK_LIB([ssl], [SSL_get_verify_result], , LLIBSSL="no")

if test "$LLIBSSL" = "no"; then
    echo
    echo "   ERROR!  openssl library not found, go get it from"
    echo "   or use the --with-openssl-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LLIBPCAP=""
AC_CHECK_LIB([pcap], [pcap_open_offline], , LLIBPCAP="no")

if test "$LLIBPCAP" = "no"; then
    echo
    echo "   ERROR!  pcap library not found, go get it from"
    echo "   or use the --with-pcap-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

AC_CONFIG_FILES([
				 Makefile
				 src/Makefile
				 ])

AC_OUTPUT
