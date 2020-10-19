/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Linux-specific stubs.
 */

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dp_test.h"

/* Same as PL_DLL_LOC */
const char *pl_path = PKGLIB_DIR"/pipeline/plugins";

static bool path_needs_redirected(const char *path)
{
	if (!path)
		return 0;
	int pathlen = strlen(path);
	bool match = false;

	match = !memcmp(path, "/proc", MIN(pathlen, strlen("/proc"))) ||
		!memcmp(path, "/sys", MIN(pathlen, strlen("/sys"))) ||
		!memcmp(path, "/run", MIN(pathlen, strlen("/run")));

	if (!from_external)
		/*
		 * Don't redirect paths if running in external mode as these
		 * need to be picked up from where the dev package put them
		 */
		match |= !memcmp(path, pl_path, MIN(pathlen, strlen(pl_path)));

	return match;
}

static int redirect_path(const char *orig_path, char *redir_path, size_t size)
{
	if (size < strlen(dp_ut_dummyfs_dir) + strlen(orig_path)) {
		*redir_path = 0;
		return -1;
	}

	if (strncmp(orig_path, pl_path, strlen(pl_path)) == 0) {
		strcpy(redir_path, "../../build/src/pipeline/nodes/sample");
		strcat(redir_path, orig_path + strlen(pl_path));
		return 0;
	}

	strcpy(redir_path, dp_ut_dummyfs_dir);
	strcat(redir_path, orig_path);

	return 0;
}

int open64(const char *file, int oflag, ...)
{
	static int (*real_open64)(const char *file, int oflag, ...);
	char redirfile[PATH_MAX];
	va_list ap;
	int ret;

	if (!real_open64)
		real_open64 = dlsym(RTLD_NEXT, "open64");

	va_start(ap, oflag);

	/*
	 * To avoid unnecessary complexity, we don't deal with the
	 * O_CREAT or O_TMPFILE semantics of calling real_open64.
	 */
	if (!(oflag & O_CREAT) && !(oflag & O_TMPFILE) &&
	    path_needs_redirected(file) &&
	    !redirect_path(file, redirfile, sizeof(redirfile))) {
		ret = real_open64(redirfile, oflag);
	} else {
		if (oflag & O_CREAT || oflag & O_TMPFILE)
			ret = real_open64(file, oflag, va_arg(ap, int));
		else
			ret = real_open64(file, oflag);
	}

	va_end(ap);

	return ret;
}

DIR *opendir(const char *name)
{
	static DIR *(*real_opendir)(const char *name);

	if (!real_opendir)
		real_opendir = dlsym(RTLD_NEXT, "opendir");

	if (path_needs_redirected(name)) {
		char redirname[PATH_MAX];

		if (!redirect_path(name, redirname, sizeof(redirname)))
			return real_opendir(redirname);
	}

	return real_opendir(name);
}

FILE *fopen(const char *__restrict filename,
	    const char *__restrict modes)
{
	static FILE *(*real_fopen)(const char *__restrict __filename,
				   const char *__restrict __modes);

	if (!real_fopen)
		real_fopen = dlsym(RTLD_NEXT, "fopen");

	if (path_needs_redirected(filename)) {
		char redirfile[PATH_MAX];

		if (!redirect_path(filename, redirfile, sizeof(redirfile)))
			return real_fopen(redirfile, modes);
	}

	return real_fopen(filename, modes);
}

FILE *fopen64(const char *__restrict filename,
	      const char *__restrict modes)
{
	static FILE *(*real_fopen64)(const char *__restrict __filename,
				   const char *__restrict __modes);

	if (!real_fopen64)
		real_fopen64 = dlsym(RTLD_NEXT, "fopen64");

	if (path_needs_redirected(filename)) {
		char redirfile[PATH_MAX];

		if (!redirect_path(filename, redirfile, sizeof(redirfile)))
			return real_fopen64(redirfile, modes);
	}

	return real_fopen64(filename, modes);
}

int access(const char *name, int type)
{
	static int (*real_access)(const char *name, int type);

	if (!real_access)
		real_access = dlsym(RTLD_NEXT, "access");

	if (path_needs_redirected(name)) {
		char redirname[PATH_MAX];

		if (!redirect_path(name, redirname, sizeof(redirname)))
			return real_access(redirname, type);
	}

	return real_access(name, type);
}

int __xstat(int ver, const char *pathname, struct stat *buf)
{
	static int (*real_xstat)(int ver, const char *pathname,
				 struct stat *buf);

	if (!real_xstat)
		real_xstat = dlsym(RTLD_NEXT, "__xstat");

	if (path_needs_redirected(pathname)) {
		char redirname[PATH_MAX];

		if (!redirect_path(pathname, redirname, sizeof(redirname)))
			return real_xstat(ver, redirname, buf);
	}

	return real_xstat(ver, pathname, buf);
}

int __xstat64(int ver, const char *pathname, struct stat64 *buf)
{
	static int (*real_xstat64)(int ver, const char *pathname,
				 struct stat64 *buf);

	if (!real_xstat64)
		real_xstat64 = dlsym(RTLD_NEXT, "__xstat64");

	if (path_needs_redirected(pathname)) {
		char redirname[PATH_MAX];

		if (!redirect_path(pathname, redirname, sizeof(redirname)))
			return real_xstat64(ver, redirname, buf);
	}

	return real_xstat64(ver, pathname, buf);
}

void *dlopen(const char *filename, int flags)
{
	static void *(*real_dlopen)(const char *filename, int flags);

	if (!real_dlopen)
		real_dlopen = dlsym(RTLD_NEXT, "dlopen");

	if (path_needs_redirected(filename)) {
		char redirname[PATH_MAX];

		if (!redirect_path(filename, redirname, sizeof(redirname)))
			return real_dlopen(redirname, flags);
	}

	return real_dlopen(filename, flags);
}
