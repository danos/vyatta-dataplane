#! /bin/sh
#
# Copyright (c) 2019, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

usage () {
    echo "Usage: $(basename $0) [target source]" >&2
    echo "Run cppcheck on the current directory"
    echo "or files in the set of diffs if target/source given"
    echo "target: something like 'origin/master'" >&2
    echo "source: something like 'bugfix/foo' or 'feature/bar'" >&2
}

cppcheck_parameters=" -q -v -j4 \
                   --error-exitcode=1 \
		   --inline-suppr \
		   --enable=warning,style,performance,portability \
		   --suppress=variableScope \
		   --suppress=allocaCalled \
		   --suppress=unusedStructMember"

if [ "$#" -eq 2 ]; then

    TARGET="$1" # most likely "origin/master"
    SOURCE="$2" # most likely "bugfix/foo" or "feature/bar"

    git diff --name-only "$(git merge-base "$SOURCE" "$TARGET")".."$SOURCE" \
	| grep -e "\.[c]$" \
	| cppcheck ${cppcheck_parameters} \
		   ${extra_cppcheck_parameters} \
		   --file-list=-

elif [ "$#" -eq 0 ]; then

    cppcheck ${cppcheck_parameters} \
	     ${extra_cppcheck_parameters} \
	     .

else
    usage
    exit 1
fi
