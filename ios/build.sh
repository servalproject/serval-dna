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

	if [[ "${ARCH}" == "i386" || "${ARCH}" == "x86_64" ]]; then
		PLATFORM="iPhoneSimulator"
	else
		PLATFORM="iPhoneOS"
	fi
  
	CROSS_TOP="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
	CROSS_SDK="${PLATFORM}${SDK_VERSION}.sdk"
	export CFLAGS="-isysroot ${CROSS_TOP}/SDKs/${CROSS_SDK} -miphoneos-version-min=${SDK_VERSION}"
	export CC="clang -arch ${ARCH}"
	
	echo "Building serval-dna for ${PLATFORM} ${SDK_VERSION} ${ARCH}"

	./configure --prefix="/tmp/serval-dna-${ARCH}" --disable-voiptest #&> "/tmp/serval-dna-${ARCH}.log"

	make >> "/tmp/serval-dna-${ARCH}.log" #2>&1
	make install >> "/tmp/serval-dna-${ARCH}.log" #2>&1
	make clean >> "/tmp/serval-dna-${ARCH}.log" #2>&1
}

# Generate configure
autoreconf -f -i

mkdir -p build/include/serval-dna
rm -rf "/tmp/serval-dna-*"

buildIOS "i386"