#!/bin/sh

#  build.sh
#  serval-dna
#
#  Created by James Moore on 3/25/14.
#  Copyright (c) 2014 The Serval Project. All rights reserved.

# Add the homebrew tools to the path since automake no longer is apart of Xcode
PATH=/usr/local/bin:$PATH
ARCHS=(arvm7 arvm7s arm64 i386 x86_64)
SDK_VERSION=7.1
DEVELOPER=`xcode-select -print-path`

set -ex

command -v autoreconf >/dev/null 2>&1 || { echo "In order to build this library you must have the autoreconf tool installed. It's available via homebrew."; exit 1; }

buildIOS()
{
	ARCH=$1
	HOST=""
	
	if [[ "${ARCH}" == "i386" ]]; then
		PLATFORM="iPhoneSimulator"
		HOST="--host=i386-apple-darwin"
	elif [[ "${ARCH}" == "x86_64" ]]; then
		PLATFORM="iPhoneSimulator"
	else
		PLATFORM="iPhoneOS"
		HOST="--host=arm-apple-darwin"
	fi
  
	CROSS_TOP="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
	CROSS_SDK="${PLATFORM}${SDK_VERSION}.sdk"
	SDKROOT="${CROSS_TOP}/SDKs/${CROSS_SDK}"
	
	export CFLAGS="-arch ${ARCH} -pipe -no-cpp-precomp -isysroot $SDKROOT -I$SDKROOT/usr/include -miphoneos-version-min=${SDK_VERSION}"
	export CC="clang"
	
	echo "Building serval-dna for ${PLATFORM} ${SDK_VERSION} ${ARCH}"

	./configure $HOST --prefix="/tmp/serval-dna-${ARCH}" --disable-voiptest #&> "/tmp/serval-dna-${ARCH}.log"

	make >> "/tmp/serval-dna-${ARCH}.log" #2>&1
	make install >> "/tmp/serval-dna-${ARCH}.log" #2>&1
	make clean >> "/tmp/serval-dna-${ARCH}.log" #2>&1
	
	# don't know why these don't get removed
	rm directory_service.o
	rm config_test.o
}

# remove duplicated function
perl -p -i -e 's/^(void rotbuf_log\(struct __sourceloc __whence, int log_level, const char \*prefix, const struct rotbuf \*rb\);)/\/\/\1/' rotbuf.h

# install -D doesn't work with the OS X install
perl -p -i -e 's/^\t\$\(INSTALL_PROGRAM\) -D servald \$\(DESTDIR\)\$\(sbindir\)\/servald/\tmkdir -p \$\(DESTDIR\)\$\(sbindir\)
\t\$\(INSTALL_PROGRAM\) servald \$\(DESTDIR\)\$\(sbindir\)\/servald/' Makefile.in

# use CFLAGS when building version file to support cross-compilation
perl -p -i -e 's/&& \$\(CC\) -c version_servald.c/&& \$\(CC\) \$\(CFLAGS\) -c version_servald.c/' Makefile.in

# Generate configure
autoreconf -f -i

mkdir -p build/include/serval-dna
rm -rf "/tmp/serval-dna-*"

buildIOS "armv7"

# for arch in $ARCHS; do
# 	buildIOS "${arch}"
# done
