/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_posix_h__
#define INCLUDE_posix_h__

#include "common.h"
#include <fcntl.h>
#include <time.h>
#include "fnmatch.h"

/* stat: file mode type testing macros */
#ifndef S_IFGITLINK
#define S_IFGITLINK 0160000
#define S_ISGITLINK(m) (((m) & S_IFMT) == S_IFGITLINK)
#endif

#ifndef S_IFLNK
#define S_IFLNK 0120000
#undef _S_IFLNK
#define _S_IFLNK S_IFLNK
#endif

#ifndef S_IXUSR
#define S_IXUSR 00100
#endif

#ifndef S_ISLNK
#define S_ISLNK(m) (((m) & _S_IFMT) == _S_IFLNK)
#endif

#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#endif

#ifndef S_ISREG
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif

#ifndef S_ISFIFO
#define S_ISFIFO(m) (((m) & _S_IFMT) == _S_IFIFO)
#endif

/* if S_ISGID is not defined, then don't try to set it */
#ifndef S_ISGID
#define S_ISGID 0
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* access() mode parameter #defines	*/
#ifndef F_OK
#define F_OK 0 /* existence check */
#endif
#ifndef W_OK
#define W_OK 2 /* write mode check */
#endif
#ifndef R_OK
#define R_OK 4 /* read mode check */
#endif

/* Determine whether an errno value indicates that a read or write failed
 * because the descriptor is blocked.
 */
#if defined(EWOULDBLOCK)
#define GIT_ISBLOCKED(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#else
#define GIT_ISBLOCKED(e) ((e) == EAGAIN)
#endif

/* define some standard errnos that the runtime may be missing.  for example,
 * mingw lacks EAFNOSUPPORT. */
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT (INT_MAX-1)
#endif

typedef int git_file;

/**
 * Standard POSIX Methods
 *
 * All the methods starting with the `p_` prefix are
 * direct ports of the standard POSIX methods.
 *
 * Some of the methods are slightly wrapped to provide
 * saner defaults. Some of these methods are emulated
 * in Windows platforms.
 *
 * Use your manpages to check the docs on these.
 */

extern ssize_t p_read(git_file fd, void *buf, size_t cnt);
extern int p_write(git_file fd, const void *buf, size_t cnt);

#define p_close(fd) close(fd)
#define p_umask(m) umask(m)

extern int p_open(const char *path, int flags, ...);
extern int p_creat(const char *path, mode_t mode);
extern int p_rename(const char *from, const char *to);

/**
 * Platform-dependent methods
 */
#include <stdio.h>
#include <dirent.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/stat.h>

typedef int GIT_SOCKET;
#define INVALID_SOCKET -1

#define p_lseek(f,n,w) lseek(f, n, w)
#define p_fstat(f,b) fstat(f, b)
#define p_lstat(p,b) lstat(p,b)
#define p_stat(p,b) stat(p, b)

#define p_utimes(f, t) utimes(f, t)

#define p_readlink(a, b, c) readlink(a, b, c)
#define p_symlink(o,n) symlink(o, n)
#define p_link(o,n) link(o, n)
#define p_unlink(p) unlink(p)
#define p_mkdir(p,m) mkdir(p, m)
#define p_fsync(fd) fsync(fd)
extern char *p_realpath(const char *, char *);

#define p_recv(s,b,l,f) recv(s,b,l,f)
#define p_send(s,b,l,f) send(s,b,l,f)
#define p_inet_pton(a, b, c) inet_pton(a, b, c)

#define p_strcasecmp(s1, s2) strcasecmp(s1, s2)
#define p_strncasecmp(s1, s2, c) strncasecmp(s1, s2, c)
#define p_vsnprintf(b, c, f, a) vsnprintf(b, c, f, a)
#define p_snprintf(b, c, f, ...) snprintf(b, c, f, __VA_ARGS__)
#define p_mkstemp(p) mkstemp(p)
#define p_chdir(p) chdir(p)
#define p_chmod(p,m) chmod(p, m)
#define p_rmdir(p) rmdir(p)
#define p_access(p,m) access(p,m)
#define p_ftruncate(fd, sz) ftruncate(fd, sz)

/* see win32/posix.h for explanation about why this exists */
#define p_lstat_posixly(p,b) lstat(p,b)

#define p_localtime_r(c, r) localtime_r(c, r)
#define p_gmtime_r(c, r) gmtime_r(c, r)

#define p_timeval timeval

#define p_futimes futimes

#ifdef NO_STRNLEN
GIT_INLINE(size_t) p_strnlen(const char *s, size_t maxlen) {
    const char *end = memchr(s, 0, maxlen);
    return end ? (size_t)(end - s) : maxlen;
}
#else
#   define p_strnlen strnlen
#endif

#ifdef NO_READDIR_R
GIT_INLINE(int) p_readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result)
{
	GIT_UNUSED(entry);
	*result = readdir(dirp);
	return 0;
}
#else /* NO_READDIR_R */
#	define p_readdir_r(d,e,r) readdir_r(d,e,r)
#endif

#ifdef NO_ADDRINFO
#	include <netdb.h>
struct addrinfo {
	struct hostent *ai_hostent;
	struct servent *ai_servent;
	struct sockaddr_in ai_addr_in;
	struct sockaddr *ai_addr;
	size_t ai_addrlen;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	long ai_port;
	struct addrinfo *ai_next;
};

extern int p_getaddrinfo(const char *host, const char *port,
	struct addrinfo *hints, struct addrinfo **info);
extern void p_freeaddrinfo(struct addrinfo *info);
extern const char *p_gai_strerror(int ret);
#else
#	define p_getaddrinfo(a, b, c, d) getaddrinfo(a, b, c, d)
#	define p_freeaddrinfo(a) freeaddrinfo(a)
#	define p_gai_strerror(c) gai_strerror(c)
#endif /* NO_ADDRINFO */

#endif
