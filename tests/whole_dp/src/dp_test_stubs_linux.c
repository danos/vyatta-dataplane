/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Linux-specific stubs.
 */

#include <stdbool.h>
#include <dlfcn.h>
#include <stdio.h>
#include <dirent.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static bool starts_with_proc_or_sys(const char *path)
{
	if (!path)
		return 0;

	return !memcmp(path, "/proc", strlen("/proc")) ||
		!memcmp(path, "/sys", strlen("/sys")) ||
		!memcmp(path, "/run", strlen("/run"));
}

static int redirect_path(const char *orig_path, char *redir_path, size_t size)
{
	if (size < strlen("tests/whole_dp/dummyfs/") + strlen(orig_path)) {
		*redir_path = 0;
		return -1;
	}

	strcpy(redir_path, "tests/whole_dp/dummyfs/");
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
	 * Redirect /proc and /sys to our dummy filesystem
	 *
	 * To avoid unnecessary complexity, we don't deal with the
	 * O_CREAT or O_TMPFILE semantics of calling real_open64.
	 */
	if (!(oflag & O_CREAT) && !(oflag & O_TMPFILE) &&
	    starts_with_proc_or_sys(file) &&
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

	/*
	 * Redirect /proc and /sys to our dummy filesystem
	 */
	if (starts_with_proc_or_sys(name)) {
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

	/*
	 * Redirect /proc and /sys to our dummy filesystem
	 */
	if (starts_with_proc_or_sys(filename)) {
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

	/*
	 * Redirect /proc and /sys to our dummy filesystem
	 */
	if (starts_with_proc_or_sys(filename)) {
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

	if (starts_with_proc_or_sys(name)) {
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

	/*
	 * Redirect /proc and /sys to our dummy filesystem
	 */
	if (starts_with_proc_or_sys(pathname)) {
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

	/*
	 * Redirect /proc and /sys to our dummy filesystem
	 */
	if (starts_with_proc_or_sys(pathname)) {
		char redirname[PATH_MAX];

		if (!redirect_path(pathname, redirname, sizeof(redirname)))
			return real_xstat64(ver, redirname, buf);
	}

	return real_xstat64(ver, pathname, buf);
}
