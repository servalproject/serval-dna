#!/bin/sh

#  build.sh
#  servald
#
#  Created by James Moore on 3/25/14.
#  Copyright (c) 2014 The Serval Project. All rights reserved.

# set -x

# if we're building inside of xcode we need to back up a level
if [[ -n $DEVELOPER_DIR ]]; then
	cd ..
	pwd
fi

# Add the homebrew tools to the path since automake no longer is apart of Xcode
PATH=/usr/local/bin:$PATH
ARCHS="armv7 armv7s arm64 i386 x86_64"
SDK_VERSION=7.1
PREFIX=$(pwd)/build
DEVELOPER=`xcode-select -print-path`

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
	
	echo "=> Building servald for ${PLATFORM} ${SDK_VERSION} ${ARCH}"

	./configure $HOST --prefix="${PREFIX}/servald-${ARCH}" --disable-voiptest &> "${PREFIX}/servald-${ARCH}.log" || { echo "configure failed"; exit 1; }

	make >> "${PREFIX}/servald-${ARCH}.log" 2>&1
	make install >> "${PREFIX}/servald-${ARCH}.log" 2>&1
	make clean >> "${PREFIX}/servald-${ARCH}.log" 2>&1
	
	# don't know why these don't get removed
	rm directory_service.o
	rm config_test.o
}

#
# Start the build
#

if [[ $ACTION == "clean" ]]; then
	echo "=> Cleaning..."
	if [[ -f ${PREFIX}/servald ]]; then
		rm ${PREFIX}/servald
	fi
	exit
fi

if [[ -f ${PREFIX}/servald ]]; then
	echo "Servald has already been build...skipping"
	exit
fi

# remove duplicated function
perl -p -i -e 's/^(void rotbuf_log\(struct __sourceloc __whence, int log_level, const char \*prefix, const struct rotbuf \*rb\);)/\/\/\1/' rotbuf.h

# install -D doesn't work with the OS X install
perl -p -i -e 's/^\t\$\(INSTALL_PROGRAM\) -D servald \$\(DESTDIR\)\$\(sbindir\)\/servald/\tmkdir -p \$\(DESTDIR\)\$\(sbindir\)
\t\$\(INSTALL_PROGRAM\) servald \$\(DESTDIR\)\$\(sbindir\)\/servald/' Makefile.in

# Generate configure
autoreconf -f -i

rm -rf ${PREFIX}/servald-*

for arch in ${ARCHS}; do
	buildIOS "${arch}"
done

echo "=> Building fat binary"

lipo \
	"${PREFIX}/servald-armv7/sbin/servald" \
	"${PREFIX}/servald-armv7s/sbin/servald" \
	"${PREFIX}/servald-arm64/sbin/servald" \
	"${PREFIX}/servald-i386/sbin/servald" \
	"${PREFIX}/servald-x86_64/sbin/servald" \
	-create -output ${PREFIX}/servald

rm -rf ${PREFIX}/servald-*

echo "=> Done"