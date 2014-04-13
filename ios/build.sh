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
SYMROOT="build"

command -v autoreconf >/dev/null 2>&1 || { echo "In order to build this library you must have the autoreconf tool installed. It's available via homebrew."; exit 1; }

buildIOS()
{
	ARCH=$1
	HOST=""
  PREFIX="/tmp/servald"
	
	if [[ "${ARCH}" == "i386" ]]; then
		PLATFORM="iPhoneSimulator"
		HOST="--host=i386-apple-darwin"
	elif [[ "${ARCH}" == "x86_64" ]]; then
		PLATFORM="iPhoneSimulator"
	else
		PLATFORM="iPhoneOS"
		HOST="--host=arm-apple-darwin"
    PREFIX="/Library/servald"
	fi
  
	CROSS_TOP="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
	CROSS_SDK="${PLATFORM}${SDK_VERSION}.sdk"
	SDKROOT="${CROSS_TOP}/SDKs/${CROSS_SDK}"

	export CFLAGS="-arch ${ARCH} -pipe -no-cpp-precomp -isysroot $SDKROOT -I$SDKROOT/usr/include -miphoneos-version-min=${SDK_VERSION}"
	export CC="clang"
	
	echo "=> Building libserval for ${PLATFORM} ${SDK_VERSION} ${ARCH}"

	./configure $HOST --prefix $PREFIX &> "${SYMROOT}/libserval-${ARCH}.log" || { echo "configure failed"; exit 1; }

	make libserval.a >> "${SYMROOT}/libserval-${ARCH}.log" 2>&1 || { echo "make failed"; exit 1; }
	cp libserval.a ${SYMROOT}/libserval-${ARCH}.a
	make clean >> "${SYMROOT}/libserval-${ARCH}.log" 2>&1 || { echo "make clean failed"; exit 1; }
	
}

#
# Start the build
#

if [[ $ACTION == "clean" ]]; then
	echo "=> Cleaning..."
	rm ${SYMROOT}/libserval.a 2> /dev/null
	rm -rf ${SYMROOT}/libserval-* 2> /dev/null
	rm -rf ${SYMROOT}/include 2> /dev/null
	exit
fi

if [[ -f ${SYMROOT}/libserval.a ]]; then
	echo "libserval has already been built...skipping"
	exit
fi

# Generate configure
autoreconf -f -i

mkdir -p ${SYMROOT}

for arch in ${ARCHS}; do
	buildIOS "${arch}"
done

echo "=> Building fat binary"

lipo \
	"${SYMROOT}/libserval-armv7.a" \
	"${SYMROOT}/libserval-armv7s.a" \
	"${SYMROOT}/libserval-arm64.a" \
	"${SYMROOT}/libserval-i386.a" \
	"${SYMROOT}/libserval-x86_64.a" \
	-create -output ${SYMROOT}/libserval.a || { echo "failed building fat library"; exit 1; }

echo "=> Copying Headers"
mkdir -p ${SYMROOT}/include
cp *.h ios/confdefs.h ${SYMROOT}/include

echo "=> Done"
