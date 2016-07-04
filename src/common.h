/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_common_h__
#define INCLUDE_common_h__

#include "posix.h"
#include "git2/common.h"
#include <stdarg.h>

#define GIT_INLINE(type) static inline type

/** Support for gcc/clang __has_builtin intrinsic */
#ifndef __has_builtin
# define __has_builtin(x) 0
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <strings.h>

#include <arpa/inet.h>

#include "git2/types.h"
#include "git2/errors.h"

#define bool int

#ifndef true
# define true (1)
#endif

#ifndef false
# define false (0)
#endif

#define GITERR_CHECK_ALLOC(ptr) if (ptr == NULL) { return -1; }

#define GIT_ADD_SIZET_OVERFLOW(out, one, two) \
	(git__add_sizet_overflow(out, one, two) ? (giterr_set_oom(), 1) : 0)

#define GIT_UNUSED(x) ((void)(x))

GIT_INLINE(bool) git__add_sizet_overflow(size_t *out, size_t one, size_t two)
{
	if (SIZE_MAX - one < two)
		return true;
	*out = one + two;
	return false;
}

GIT_INLINE(int) git__is_ssizet(size_t p)
{
	ssize_t r = (ssize_t)p;
	return p == (size_t)r;
}

GIT_INLINE(void *) git__malloc(size_t len)
{
    void *ptr = malloc(len);
    if (!ptr) giterr_set_oom();
    return ptr;
}

GIT_INLINE(void *) git__calloc(size_t nelem, size_t elsize)
{
    void *ptr = calloc(nelem, elsize);
    if (!ptr) giterr_set_oom();
    return ptr;
}

GIT_INLINE(char *) git__strdup(const char *str)
{
    char *ptr = strdup(str);
    if (!ptr) giterr_set_oom();
    return ptr;
}

GIT_INLINE(void) git__free(void *ptr)
{
    free(ptr);
}

GIT_INLINE(char *) git__strndup(const char *str, size_t n)
{
	size_t length = 0, alloclength;
	char *ptr;

	length = p_strnlen(str, n);

	if (GIT_ADD_SIZET_OVERFLOW(&alloclength, length, 1) ||
		!(ptr = git__malloc(alloclength)))
		return NULL;

	if (length)
		memcpy(ptr, str, length);

	ptr[length] = '\0';

	return ptr;
}

#define git__tolower(a) tolower(a)

GIT_INLINE(int) git__prefixcmp(const char *str, const char *prefix)
{
	for (;;) {
		unsigned char p = *(prefix++), s;
		if (!p)
			return 0;
		if ((s = *(str++)) != p)
			return s - p;
	}
}

GIT_INLINE(char *) git__substrdup(const char *start, size_t n)
{
	char *ptr;
	size_t alloclen;

	if (GIT_ADD_SIZET_OVERFLOW(&alloclen, n, 1) ||
		!(ptr = git__malloc(alloclen)))
		return NULL;

	memcpy(ptr, start, n);
	ptr[n] = '\0';
	return ptr;
}


#endif /* INCLUDE_common_h__ */
