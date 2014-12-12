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
   echo "Usage: $ME [options] [--] [<refspec>]"'

Produces a version string for the commit <refspec> (current working copy by
default) of the given Git repository (current working directory by default).
The version string has the following form:

   D.D[extra] [ -N-gXXXXXXX ] [ +USER-YYYYMMDDHHMMSS ]

Where:
   D.D[extra]           is the most recent version tag prior to HEAD, eg,
                        0.91.RC2; if there is no tag, then a default tag of
                        "START" is used to represent the first commit in the
                        repository
   -N-gXXXXXXX          is appended if there are any commits since the version
                        tag; N is the number of commits, XXXXXXX is the
                        abbreviated Git commit Id
   +USER-YYYYMMDDHHMMSS is appended if <refspec> is omitted or empty and the
                        current working copy has local modifications; USER is
                        the email address of the user who owns the repository,
                        YYYYMMDDHHMMSS is the current local time

Options:
   --help               Show this message
   --repository=PATH    Use repository at PATH instead of the current working
                        directory
   --ignore-untracked   Do not count any untracked local changes to determine
                        whether the version is locally modified
   --unmodified         Fail with an error if there are any local modifications
                        instead of appending the +USER-YYYYMMDDHHMMSS suffix
   --no-default-tag     If no version tag is found, then fail with an error
                        instead of producing a version relative to the default
                        "START" tag
   --default-tag=TAG    Use "TAG" instead of "START" for the default tag if no
                        version tag is found
'
}

ME="${0##*/}"

set -e

refspec=
allow_modified=true
untracked_files=normal
ignore_submodules=none
default_tag="START"
repo_path=.
version_tag_glob='[0-9].[0-9]*'

while [ $# -gt 0 ]; do
   case "$1" in
   --help) usage; exit 0;;
   --repository=*) repo_path="${1#*=}";;
   --ignore-untracked) untracked_files=no; ignore_submodules=untracked;;
   --unmodified) allow_modified=false;;
   --no-default-tag) default_tag=;;
   --default-tag=*) default_tag="${1#*=}";;
   --) shift; break;;
   -*)
      echo "$ME: unrecognised option: $1" >&2
      echo "Try \`$ME --help' for more information." >&2
      exit 1
      ;;
   *) break;;
   esac
   shift
done

case $# in
0);;
1) refspec="$1";;
*)
   echo "$ME: too many arguments" >&2
   echo "Try \`$ME --help' for more information." >&2
   exit 1
   ;;
esac

cd "$repo_path" >/dev/null

if test "z$(git rev-parse --is-bare-repository 2>/dev/null)" != zfalse; then
   if [ -s VERSION.txt ] && [ $(cat VERSION.txt | wc -l) -eq 1 ]; then
      cat VERSION.txt
   else
      echo "UNKNOWN-VERSION"
   fi
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

dirty=
if [ -z "$refspec" ]; then
   # The --dirty option to "git describe" always counts untracked changes as dirt.
   # In order to implement the --ignore-untracked and --unmodified options, use the
   # "git status" command to detect local modifications.
   if [ $(git status --porcelain --untracked-files=$untracked_files --ignore-submodules=$ignore_submodules 2>/dev/null | wc -l) -ne 0 ]; then
      get_author_label
      dirty="+$author_label-$(date '+%Y%m%d%H%M%S')"
   fi
fi

if [ -n "$dirty" ] && ! $allow_modified; then
   echo "$ME: cannot form version string for repository: $(pwd -P)" >&2
   echo "$ME: repository has local modifications" >&2
   exit 3
fi

# Use the "git describe" command to form the version string
if version="$(git describe --match="$version_tag_glob" $refspec 2>/dev/null)"; then
   echo "${version}${dirty}"
   exit 0
fi

# If the describe failed because there are no annotated version tags in the
# ancestry, and we know a default tag, then we synthesize the version string
# ourselves.
if [ -n "$default_tag" ]; then
   commit=$(git rev-list --abbrev-commit --max-count=1 ${refspec:-HEAD})
   count=$(( $(git rev-list ${refspec:-HEAD} | wc -l) - 1 ))
   echo "$default_tag-$count-g$commit$dirty"
   exit 0
fi

echo "$ME: cannot form version string for repository: $(pwd -P)" >&2
exit 2
