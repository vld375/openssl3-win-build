package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
    @PREFIX
    @libdir
    @BINDIR @BINDIR_REL_PREFIX
    @LIBDIR @LIBDIR_REL_PREFIX
    @INCLUDEDIR @INCLUDEDIR_REL_PREFIX
    @APPLINKDIR @APPLINKDIR_REL_PREFIX
    @ENGINESDIR @ENGINESDIR_REL_LIBDIR
    @MODULESDIR @MODULESDIR_REL_LIBDIR
    @PKGCONFIGDIR @PKGCONFIGDIR_REL_LIBDIR
    @CMAKECONFIGDIR @CMAKECONFIGDIR_REL_LIBDIR
    $VERSION @LDLIBS
);

our @PREFIX                     = ( 'D:\prj\LWOCRYPT_PROV\openssl3-win-build' );
our @libdir                     = ( 'D:\prj\LWOCRYPT_PROV\openssl3-win-build' );
our @BINDIR                     = ( 'D:\prj\LWOCRYPT_PROV\openssl3-win-build\apps' );
our @BINDIR_REL_PREFIX          = ( 'apps' );
our @LIBDIR                     = ( 'D:\prj\LWOCRYPT_PROV\openssl3-win-build' );
our @LIBDIR_REL_PREFIX          = ( '' );
our @INCLUDEDIR                 = ( 'D:\prj\LWOCRYPT_PROV\openssl3-win-build\include', 'D:\prj\LWOCRYPT_PROV\openssl3-win-build\include' );
our @INCLUDEDIR_REL_PREFIX      = ( 'include', './include' );
our @APPLINKDIR                 = ( 'D:\prj\LWOCRYPT_PROV\openssl3-win-build\ms' );
our @APPLINKDIR_REL_PREFIX      = ( 'ms' );
our @ENGINESDIR                 = ( 'D:\prj\LWOCRYPT_PROV\openssl3-win-build\engines' );
our @ENGINESDIR_REL_LIBDIR      = ( 'engines' );
our @MODULESDIR                 = ( 'D:\prj\LWOCRYPT_PROV\openssl3-win-build\providers' );
our @MODULESDIR_REL_LIBDIR      = ( 'providers' );
our @PKGCONFIGDIR               = ( 'D:\prj\LWOCRYPT_PROV\openssl3-win-build' );
our @PKGCONFIGDIR_REL_LIBDIR    = ( '.' );
our @CMAKECONFIGDIR             = ( 'D:\prj\LWOCRYPT_PROV\openssl3-win-build' );
our @CMAKECONFIGDIR_REL_LIBDIR  = ( '.' );
our $VERSION                    = '3.6.0';
our @LDLIBS                     =
    # Unix and Windows use space separation, VMS uses comma separation
    $^O eq 'VMS'
    ? split(/ *, */, 'ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib ')
    : split(/ +/, 'ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib ');

1;
