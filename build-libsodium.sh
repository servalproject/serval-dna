#!/bin/bash
#
# Copyright (C) 2016 Serval Project, Inc.
#
# This script downloads the libsodium source code from GitHub, then compiles it
# and sets up the Serval DNA source code to build against the compiled
# libsodium.
#
# This script is useful for building Serval DNA on platforms such as Max OS X
# that do not provide the libsodium development package.  Debian and Ubuntu
# provide the libsodium-dev package which can be installed instead of using this
# script.
#
# By default, the script creates a 'libsodium' directory in the same directory
# that contains the 'serval-dna' directory, ie, '../libsodium' relative to the
# script.  This location can be overridden by giving an alternative directory
# path on the command line, which the script will create if it does not exist.

usage() {
   echo "Usage: ${0##*/} [--directory PATH] [--ssh] [--make-arg ARG]"
   echo "Options:  --src PATH          download and build in PATH [$LIBSODIUM_BUILD_DIR]"
   echo "          --prefix PATH       install into PATH [$LIBSODIUM_INSTALL_DIR]"
   echo "          --no-update         do not update if already downloaded"
   echo "          --no-clean          do not clean if already built"
   echo "          --ssh               download from GitHub using SSH instead of HTTPS"
   echo "          --dist-build DIST   build using libsodium's 'dist-build/DIST.sh' script"
   echo "          --make-arg ARG      pass ARG to the 'make' command"
}

# Work out the path of the directory that contains this script.
case "$0" in
*/*) SCRIPT_DIR="${0%/*}";;
*) SCRIPT_DIR=".";;
esac
case "$SCRIPT_DIR" in
*/*) SCRIPT_PARENT_DIR="${SCRIPT_DIR%/*}";;
.) SCRIPT_PARENT_DIR="..";;
*) SCRIPT_PARENT_DIR="$SCRIPT_DIR/..";;
esac

# Download location.
LIBSODIUM_URL_PATH="jedisct1/libsodium.git"
LIBSODIUM_GIT_URL_HTTPS="https://github.com/$LIBSODIUM_URL_PATH"
LIBSODIUM_GIT_URL_SSH="git@github.com:$LIBSODIUM_URL_PATH"
LIBSODIUM_GIT_URL="$LIBSODIUM_GIT_URL_HTTPS"

# The directory in which to install the built libsodium.
LIBSODIUM_INSTALL_DIR="$SCRIPT_DIR/libsodium"

# The directory in which to download and build libsodium.
LIBSODIUM_BUILD_DIR="$SCRIPT_PARENT_DIR/libsodium"

# Exit on error
set -e

usage_error() {
   echo "${0##*/}: $*" >&2
   usage >&2
   exit 1
}

fatal() {
   echo "${0##*/}: $*" >&2
   exit 1
}

# Parse the command-line, preserving all the arguments for later reference.
PRESERVED_ARGS=()
OPT_UPDATE=true
OPT_CLEAN=true
DIST=
MAKE_ARGS=()
while [ $# -ne 0 ]; do
   opt="$1"
   shift
   case "$opt" in
   -h | --help | '-?' )
      usage
      exit 0
      ;;
   --src=*)
      PRESERVED_ARGS+=("$opt")
      LIBSODIUM_BUILD_DIR="${opt#*=}"
      ;;
   --src)
      [ $# -ge 1 ] || usage_error "missing argument after $opt"
      PRESERVED_ARGS+=("$opt" "$1")
      LIBSODIUM_BUILD_DIR="$1"
      shift
      ;;
   --prefix=*)
      PRESERVED_ARGS+=("$opt")
      LIBSODIUM_INSTALL_DIR="${opt#*=}"
      ;;
   --prefix)
      [ $# -ge 1 ] || usage_error "missing argument after $opt"
      PRESERVED_ARGS+=("$opt" "$1")
      LIBSODIUM_INSTALL_DIR="$1"
      shift
      ;;
   --ssh)
      PRESERVED_ARGS+=("$opt")
      LIBSODIUM_GIT_URL="$LIBSODIUM_GIT_URL_SSH"
      ;;
   --no-update)
      OPT_UPDATE=false
      ;;
   --no-clean)
      OPT_CLEAN=false
      ;;
   --dist-build=*)
      PRESERVED_ARGS+=("$opt")
      DIST="${opt#*=}"
      ;;
   --dist-build)
      [ $# -ge 1 ] || usage_error "missing argument after $opt"
      PRESERVED_ARGS+=("$opt" "$1")
      DIST="$1"
      shift
      ;;
   --make-arg=*)
      PRESERVED_ARGS+=("$opt")
      MAKE_ARGS+=("${opt#*=}")
      ;;
   --make-arg)
      [ $# -ge 1 ] || usage_error "missing argument after $opt"
      PRESERVED_ARGS+=("$opt" "$1")
      MAKE_ARGS+=("$1")
      shift
      ;;
   -*)
      usage_error "unrecognised option: $1"
      ;;
   *)
      usage_error "spurious argument: $1"
      ;;
   esac
done

abspath() {
   case "$1" in
   /*) echo "$1";;
   .) echo "$PWD";;
   *) echo "$PWD/${1#./}";;
   esac
}

if [ ! -d "$LIBSODIUM_BUILD_DIR" ]; then
   echo "Create $LIBSODIUM_BUILD_DIR"
   mkdir -p "$LIBSODIUM_BUILD_DIR"
fi

LIBSODIUM_INSTALL_ABSDIR="$(abspath "$LIBSODIUM_INSTALL_DIR")"

is_libsodium_downloaded() {
   [ -r "$1/src/libsodium/include/sodium.h" -a \
     -r "$1/libsodium-uninstalled.pc.in" \
   ]
}

if ! is_libsodium_downloaded "$LIBSODIUM_BUILD_DIR"; then
   echo "Download libsodium from $LIBSODIUM_GIT_URL..."
   git clone --branch stable "$LIBSODIUM_GIT_URL" "$LIBSODIUM_BUILD_DIR"
   cd "$LIBSODIUM_BUILD_DIR" >/dev/null
   is_libsodium_downloaded . || fatal "Download did not produce expected source files"
else
   echo "Libsodium appears to already be downloaded"
   cd "$LIBSODIUM_BUILD_DIR" >/dev/null
   git checkout stable
   if $OPT_UPDATE; then
      echo "Update from" $(git remote get-url origin)
      git pull --ff-only origin stable
   fi
fi

if [ -d "$LIBSODIUM_INSTALL_ABSDIR" ]; then
   echo "Delete the previous installation"
   rm -rf "$LIBSODIUM_INSTALL_ABSDIR"
fi

if $OPT_CLEAN && [ -r Makefile ]; then
   echo "Clean the previous build"
   make distclean >/dev/null
fi

if [ -z "$DIST" ]; then
   echo "Native build..."
   [ -r Makefile ] || ./configure --prefix="$LIBSODIUM_INSTALL_ABSDIR"
   make -j3 "${MAKE_ARGS[@]}" check
   make -j3 "${MAKE_ARGS[@]}" install
elif [ -x "dist-build/$DIST.sh" ]; then
   installed="libsodium-$DIST"
   case "$DIST" in
   arm) installed="libsodium-armv6";;
   esac
   [ -e "$installed" ] && fatal "previous build remains in $installed"
   echo "Build using 'dist-build/$DIST.sh'..."
   "dist-build/$DIST.sh"
   [ -d "$installed" ] || fatal "build did not produce $installed"
   echo "Copy built installation into $LIBSODIUM_INSTALL_ABSDIR"
   cp -R -p "$installed" "$LIBSODIUM_INSTALL_ABSDIR"
else
   fatal "script "dist-build/$DIST_BUILD.sh" does not exist."
fi

# Create a shell script that will set up the environment to use the built and
# installed libsodium.
cat >"$LIBSODIUM_INSTALL_ABSDIR/settings.sh" <<EOF
# libsodium development and run-time environment settings
#
# Source this file using the Bash "source" or Shell "." command to set up the
# environment so that compilation and execution will use the libsodium
# installed in this directory.
#
# NOTE: This file was generated by running the ${0##*/} script.
# If you edit this file, any changes will be overwritten the next time that
# script is run.

# Compiler settings:
export CPPFLAGS="\$CPPFLAGS -isystem $LIBSODIUM_INSTALL_ABSDIR/include"
export LIBRARY_PATH="$LIBSODIUM_INSTALL_ABSDIR/lib"

# Run-time settings:
export LD_LIBRARY_PATH="\${LD_LIBRARY_PATH:+\$LD_LIBRARY_PATH:}$LIBSODIUM_INSTALL_ABSDIR/lib"
EOF

# Create a README.txt file.
cat >"$LIBSODIUM_INSTALL_ABSDIR/README.txt" <<EOF
This directory is a local installation of the libsodium cryptographic library
downloaded from $LIBSODIUM_GIT_URL

It was downloaded and built locally using the command:
${0##*/} ${PRESERVED_ARGS[*]}
EOF

echo
echo "The libsodium run-time and development files have been installed in:"
echo "$LIBSODIUM_INSTALL_ABSDIR"
echo
echo "To use this installation of libsodium, set up the environment using the"
echo "shell's \"dot\" command to source its settings.sh script, for example:"
echo
echo "   . $LIBSODIUM_INSTALL_DIR/settings.sh ; ./configure"
echo
