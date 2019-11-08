#! /bin/sh

# Append '_VR' to log file name so it's unique

if [ -n "$CK_LOG_FILE_NAME" ]; then
    export CK_LOG_FILE_NAME="${CK_LOG_FILE_NAME}_VR"
fi

if [ -n "$CK_XML_LOG_FILE_NAME" ]; then
    export CK_XML_LOG_FILE_NAME="${CK_XML_LOG_FILE_NAME}_VR"
fi

if [ -n "$CK_TAP_LOG_FILE_NAME" ]; then
    export CK_TAP_LOG_FILE_NAME="${CK_TAP_LOG_FILE_NAME}_VR"
fi

# Valgrind thinks catchsegv leaks badly, so don't use it!
if [ -z "$VALGRIND" ]; then
    CATCHSEGV="catchsegv"
fi

${CATCHSEGV} ./dataplane_test "$@"
