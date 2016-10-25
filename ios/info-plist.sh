#!/bin/bash

# Utility to output an Apple framework Info.plist file for Serval DNA.
# Copyright 2017 Flinders University

set -e

case "$0" in
*/*) SERVAL_DNA_DIR="${0%/*}/..";;
*)   SERVAL_DNA_DIR="..";;
esac

bundle_name="${1?}"
bundle_id="${2?}"
bundle_version="${3?}"

escape() {
   echo -n "$(printf '%s\n' "$*" | sed -e 's/&/&amp;/g' -e 's/</&lt;/g' -e 's/>/&gt;/g')"
}

comment() {
   echo '<!--'
   local arg
   for arg; do
      printf '    %s\n' "$arg" | sed -e 's/-->/-- >/g'
   done
   echo '-->'
}

property() {
   echo -n '    <key>'
   escape "$1"
   echo -n '</key><string>'
   escape "$2"
   echo '</string>'
}

echo '<?xml version="1.0" encoding="UTF-8"?>'
echo '<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
comment "Info.plist for the $bundle_name framework iOS bundle." \
        "Copyright 2007 Flinders University"
echo '<plist version="1.0">'
echo '<dict>'
property CFBundleIdentifier            "$bundle_id"
property CFBundleName                  "$bundle_name"
property CFBundleVersion               "$bundle_version"
property CFBundleShortVersionString    "$bundle_version"
property CFBundleExecutable            "$bundle_name"
property CFBundleDevelopmentRegion     English
property CFBundleInfoDictionaryVersion 6.0
property CFBundlePackageType           FMWK
property NSHumanReadableCopyright      "$(cat $SERVAL_DNA_DIR/COPYRIGHT.txt)"
echo '</dict>'
echo '</plist>'
