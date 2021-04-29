#! /bin/bash
# Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.

usage () {
    echo "Usage: $(basename $0) target source" >&2
    echo "target: something like 'origin/master'" >&2
    echo "source: something like 'bugfix/foo' or 'feature/bar'" >&2
}

[ "$#" -ne 2 ] && { usage; exit 1; }

TARGET="$1" # most likely "origin/master"
SOURCE="$2" # most likely "bugfix/foo" or "feature/bar"

GIT_SOURCE_HASH=$(git rev-list -n1 "$SOURCE")
GIT_TARGET_HASH=$(git rev-list -n1 "$TARGET")
GIT_MERGE_BASE=$(git merge-base $GIT_SOURCE_HASH $GIT_TARGET_HASH)

checkpatch.pl --git  "$GIT_MERGE_BASE..$GIT_SOURCE_HASH"
CHECKPATCH_EXIT_STATUS=$?

if [ $CHECKPATCH_EXIT_STATUS -ne 0 ]; then
    exit 1
fi
