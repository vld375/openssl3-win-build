#! /usr/bin/env perl
# Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw(:DEFAULT bldtop_dir bldtop_file shlib_dir shlib_file);
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;
use Cwd qw(abs_path);

setup("test_internal_provider");

#$ENV{OPENSSL_MODULES} = bldtop_dir("test");
#$ENV{OPENSSL_CONF} = bldtop_file("test", "provider_internal_test.cnf");
$ENV{OPENSSL_MODULES} = abs_path(shlib_dir());
$ENV{OPENSSL_CONF} = shlib_file("provider_internal_test.cnf");

simple_test("test_internal_provider", "provider_internal_test");
