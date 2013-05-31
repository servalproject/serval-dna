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

set -e

get_author_label() {
   # See git-commit-tree(1) for the semantics of working out the author's email
   # address when committing.
   local email
   email="${GIT_AUTHOR_EMAIL:-${GIT_COMMITTER_EMAIL:-${EMAIL:-$(git config --get user.email || true)}}}"
   # Serval Project email addresses get special treatment, to reduce day-to-day
   # version string verbosity.
   case "$email" in
   '') author_label="${LOGNAME?}@$(hostname --fqdn)";;
   *@servalproject.org) author_label="${email%@*}";;
   *) author_label="$email";;
   esac
}

dirty=
dirtyfiles=$(git status --short --untracked-files=no)
if [ -n "$dirtyfiles" ]; then
   get_author_label
   dirty="+$author_label-$(date '+%Y%m%d%H%M%S')"
fi

if ! git describe "${dirty:+--dirty=$dirty}" 2>/dev/null; then
   original_commit=$(git rev-list --reverse --max-parents=0 --abbrev-commit HEAD 2>/dev/null | head -n 1)
   if [ -z "$original_commit" ]; then
      original_commit=$(git rev-list --reverse --abbrev-commit HEAD | head -n 1)
   fi
   if [ -z "$original_commit" ]; then
      echo "$0: original commit unknown" >&2
      exit 1
   fi
   existing_start_tag="$(git rev-list --no-walk START 2>/dev/null | true)"
   if [ -n "$(git tag --list START 2>/dev/null)" -a "$existing_start_tag" != "$original_commit" ]; then
      echo "$0: tag 'START' is already in use" >&2
      exit 1
   fi
   if [ -z "$existing_start_tag" ]; then
      git tag START $original_commit
   fi
   git describe --dirty="$dirty" --tags
   if [ -z "$existing_start_tag" ]; then
      git tag -d START >/dev/null
   fi
fi
