#!/bin/sh

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
	
	echo "=> Building libserval for ${PLATFORM} ${SDK_VERSION} ${ARCH}"

	./configure $HOST --disable-voiptest &> "${PREFIX}/libserval-${ARCH}.log" || { echo "configure failed"; exit 1; }

	make libserval.a >> "${PREFIX}/libserval-${ARCH}.log" 2>&1 || { echo "make failed"; exit 1; }
	cp libserval.a ${PREFIX}/libserval-${ARCH}.a
	make clean >> "${PREFIX}/libserval-${ARCH}.log" 2>&1 || { echo "make clean failed"; exit 1; }
	
	# don't know why these don't get removed
	# rm directory_service.o
	# rm config_test.o
}

#
# Start the build
#

if [[ $ACTION == "clean" ]]; then
	echo "=> Cleaning..."
	if [[ -f ${PREFIX}/libserval.a ]]; then
		rm ${PREFIX}/libserval.a
		rm -rf ${PREFIX}/libserval-*
		rm -rf ${PREFIX}/include
	fi
	exit
fi

if [[ -f ${PREFIX}/libserval.a ]]; then
	echo "libserval has already been built...skipping"
	exit
fi

# remove duplicated function
perl -p -i -e 's/^(void rotbuf_log\(struct __sourceloc __whence, int log_level, const char \*prefix, const struct rotbuf \*rb\);)/\/\/\1/' rotbuf.h

# Generate configure
autoreconf -f -i

mkdir -p ${PREFIX}

for arch in ${ARCHS}; do
	buildIOS "${arch}"
done

echo "=> Building fat binary"

lipo \
	"${PREFIX}/libserval-armv7.a" \
	"${PREFIX}/libserval-armv7s.a" \
	"${PREFIX}/libserval-arm64.a" \
	"${PREFIX}/libserval-i386.a" \
	"${PREFIX}/libserval-x86_64.a" \
	-create -output ${PREFIX}/libserval.a || { echo "failed building fat library"; exit 1; }

echo "=> Copying Headers"
mkdir -p ${PREFIX}/include
cp *.h ios/confdefs.h ${PREFIX}/include

# Roll back the changes we made to these files
if [[ -d ".git" ]]; then
	git checkout -- Makefile.in
	git checkout -- rotbuf.h
fi

echo "=> Done"
