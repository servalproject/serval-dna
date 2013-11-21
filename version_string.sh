#!/bin/sh

# Serval Project Serval DNA version string generator
# Copyright 2013 Serval Project, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

usage() {
   echo "Usage: ${0##*/} [options]"'

Produces a version string for the HEAD of the Git repository in the current
working directory.  The version string has the following form:

   D.D[extra] [ -N-gXXXXXXX ] [ +USER-YYYYMMDDHHMMSS ]

Where:
   D.D[extra]              is the most recent version tag prior to HEAD, eg,
                           0.91.RC2; if there is no tag, then a default tag
                           of "START" is used to represent the first commit in
                           the repository
   -N-gXXXXXXX             is appended if there are any commits since the
                           version tag; N is the number of commits, XXXXXXX is
                           the abbreviated Git commit Id
   +USER-YYYYMMDDHHMMSS    is appended if there are any local modifications;
                           USER is the email address of the user who owns the
                           repository, YYYYMMDDHHMMSS is the current local time

Options:
   --help               Show this message
   --ignore-untracked   Do not count any untracked local changes to determine
                        whether the version is locally modified
   --unmodified         Fail with an error if there are any local modifications
                        instead of appending the +USER-YYYYMMDDHHMMSS suffix
   --no-default-tag     If no version tag is found, then fail with an error
                        instead of producing a version relative to the default
                        "START" tag
   --default-tag=TAG    Use "TAG" instead of "START" for the default tag if no
                        version tag is found
   --repository=PATH    Produce a version string for the repository in the
                        directory at PATH instead of the current working
                        directory
'
}

set -e

allow_modified=true
untracked_files=normal
ignore_submodules=none
default_tag="START"
repo_path=.
version_tag_glob='[0-9].[0-9]*'

while [ $# -gt 0 ]; do
   case "$1" in
   --help) usage; exit 0;;
   --ignore-untracked) untracked_files=no; ignore_submodules=untracked; shift;;
   --unmodified) allow_modified=false; shift;;
   --no-default-tag) default_tag=; shift;;
   --default-tag=*) default_tag="${1#*=}"; shift;;
   --repository=*) repo_path="${1#*=}"; shift;;
   *)
      echo "$0: unrecognised option: $1" >&2
      echo "Try \`${0##*/} --help' for more information." >&2
      exit 1
      ;;
   esac
done

cd "$repo_path" >/dev/null

if [ ! -d .git ]; then
  echo "UNKNOWN-VERSION"
  exit 0
fi

get_author_label() {
   # See git-commit-tree(1) for the semantics of working out the author's email
   # address when committing.
   local email
   email="${GIT_AUTHOR_EMAIL:-${GIT_COMMITTER_EMAIL:-${EMAIL:-$(git config --get user.email 2>/dev/null || true)}}}"
   # Serval Project email addresses get special treatment, to reduce day-to-day
   # version string verbosity.
   case "$email" in
   '') author_label="${LOGNAME?}@$(hostname --fqdn)";; #" <-- fix Vim syntax highlighting
   *@servalproject.org) author_label="${email%@*}";; #" <-- fix Vim syntax highlighting
   *) author_label="$email";;
   esac
}

# The --dirty option to "git describe" always counts untracked changes as dirt.
# In order to implement the --ignore-untracked and --unmodified options, use the
# "git status" command to detect local modifications.
dirty=
if [ $(git status --porcelain --untracked-files=$untracked_files --ignore-submodules=$ignore_submodules 2>/dev/null | wc -l) -ne 0 ]; then
   get_author_label
   dirty="+$author_label-$(date '+%Y%m%d%H%M%S')"
fi
if [ -n "$dirty" ] && ! $allow_modified; then
   echo "$0: cannot form version string for repository: $(pwd -P)" >&2
   echo "$0: repository has local modifications" >&2
   exit 3
fi

# Use the "git describe" command to form the version string and append $dirty.
# This ugly construction is required for use on machines with bash version < 4.
error="$(git describe --match="$version_tag_glob" 2>&1 1>/dev/null)" || true

if [ -z "$error" ]; then
   echo "$(git describe --match="$version_tag_glob")$dirty"
   exit 0
fi

# If the describe failed because there are no annotated version tags in the
# ancestry, and we know a default tag, then we synthesize the version string
# ourselves.
case "$error" in
*[Nn]'o names found'* | \
*[Nn]'o tags can describe'* | \
*[Cc]'annot describe'* )
   if [ -n "$default_tag" ]; then
      commit=$(git rev-list --abbrev-commit --max-count 1 HEAD)
      count=$(( $(git rev-list HEAD | wc -l) - 1 ))
      echo "$default_tag-$count-g$commit$dirty"
      exit 0
   fi
   ;;
esac

echo "$0: cannot form version string for repository: $(pwd -P)" >&2
echo "$0: git returned: ${error#fatal: }" >&2
exit 2
