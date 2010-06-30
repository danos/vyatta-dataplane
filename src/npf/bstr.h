/*
 * Copyright 2010, Derek Fawcus.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/**
 * @file   bstr.h
 * @brief  An abstraction for counted strings.
 *
 * @author Derek Fawcus
 * @date   June 2010
 *
 * This provides an abstraction for counted strings,  and APIs for
 * manipulating them.  Equivalent types and APIs have been invented
 * numerous times.  The flavour for this implementation is inspired
 * by the 'struct strbuf' and manipulators found in the git source.
 *
 * There are a few differences.  The main differences being that
 * this implementation limits the string length (to 32766 bytes),
 * that it supports fixed capacity as well as dynamially growable
 * (up to the above limit) strings,  and that it returns success
 * or failure codes rather than simply crashing.
 *
 * This is now tunable, depending upon the setting of BSTR_SMALL.
 *
 * The size limit is for pragmatic reasons,  providing a reasonable
 * length on an embedded system,  and ensuring that allocations do
 * not become too big.  It also balances the size of the type itself
 * against its capacity.  On an ILP32 system,  the type will be
 * 8 bytes long,  on a LP64 system it will be 12 bytes.
 *
 * When not using BSTR_SMALL forms, then the ILP32 size will be
 * 12 bytes, and the LP64 size will be 16 bytes.
 *
 * Dynamically growable strings are backed by malloc/free.  Support
 * for fixed capacity strings is to allow easy use at interrupt level,
 * and to maintain compatibility with the existing usage patterns.
 *
 * Typical use would be to build up a descriptive string in multiple
 * calls without risking suspending, and then pass the build string to
 * printf() which may suspend.
 *
 * The code always ensures that once initialsed (either by the static
 * initialiser BSTR_INIT,  or via calling bstr_init()),  the
 * string will always be '\0' terminated,  and that the ->buf element
 * will be valid.  Hence maintaining easy of use and compatibility
 * with generic 'c strings'.
 *
 * Example use of dynamic string (error checking omitted):
 * @code
 * void foo (ptr_t *ptr)
 * {
 *     bstr_t sb;
 *
 *     bstr_init(&sb, 200);
 *     bstr_addstr(&sb, "Literal cstring text, ");
 *     bstr_addbuf(&sb, BSTRL("Literal bstr text, "));
 *     bstr_addf(&sb, "name %s, ", ptr->some_string);
 *     bstr_addf(&sb, "id %d", ptr->some_int);
 *     // Now the string is formed, and we can print it.
 *     printf("%s, length %d", sb.buf, sb.len);
 *     bstr_release(&sb);
 * }
 * @endcode
 *
 * Example use of fixed capacity string (error checking omitted):
 * @code
 * void foo (ptr_t *ptr)
 * {
 * #define MY_SIZE_BUF 200
 *     char buf[MY_SIZE_BUF];
 *     bstr_t sb = BSTR_INIT;
 *
 *     bstr_attach_unmanaged(&sb, buf, 0, sizeof buf);
 *     bstr_add(&sb, "Foo", sizeof "Foo" - 1);
 *     bstr_addch(&sb, '!');
 *     printf("%s", sb.buf);
 *
 *     bstr_reset(&sb); // Back to empty using same storage
 *     bstr_addstr(&sb, "Bar");
 *     printf("%s", sb.buf);
 * }
 * @endcode
 */
#ifndef __BSTR_H__
#define __BSTR_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/**
 * Type definition for the string buffer types for use in function prototypes.
 *
 * @opaque_struct
 */
typedef struct bstr_t_ bstr_t;

/**
 * Adjust to control maximum capacity of strings.
 */
#define BSTR_SMALL 0

/**
 * One should not access the ->allocated member as its encoding is private.
 * The buf and len members may be accessed.
 *
 * Hence this is a semi-opaque struct.
 */
#if BSTR_SMALL
struct bstr_t_ {
	uint8_t *buf;
	int16_t len;
	uint16_t allocated;
};
#else
struct bstr_t_ {
	uint8_t *buf;
	int32_t len;
	uint32_t allocated;
};
#endif /* BSTR_SMALL */

/*
 * Only visible for the below init macro - do not reference directly.
 */
extern uint8_t bstr_empty[];

/*
 * Initialisation value a bstr variable.
 */
#define BSTR_INIT (struct bstr_t_){bstr_empty, 0, 0}

/*
 * Useful for constants in array / structure definitions.
 */
#define BSTR_K(str) {.buf = (uint8_t *)(str), .len = sizeof (str) - 1, .allocated = sizeof (str)}

/*
 * Building blocks for the BSTRL() macro.
 *
 * The GCC form uses all 'static' data, hence is fully constructed at compile time.
 * The STANDARD form has a 'static' buffer, but an 'auto' struct,
 * hence it is partially run time constructed.
 *
 * The GCC form is also safer, in that it fails to compile if the argument is not
 * a quoted string.
 */
#define BSTRL_GCC(str) ({static const uint8_t _bc[] = (str); static const bstr_t _bb = BSTR_K(_bc); &_bb;})
#define BSTRL_STANDARD(str) (&(const bstr_t)BSTR_K(str))

/* A Literal string */
#ifdef __GNUC__
 #define BSTRL(str) BSTRL_GCC(str)
#else
 #define BSTRL(str) BSTRL_STANDARD(str)
#endif /* __GNUC__ */

/*
 * create/destroy/management
 */
bool bstr_init(bstr_t *bs, int length_hint);
void bstr_release(bstr_t *bs);
void *bstr_detach(bstr_t *bs, int *length, bool *managed);
bool bstr_attach_managed(bstr_t *bs, void *str, int str_len, int alloc);
bool bstr_attach_unmanaged(bstr_t *bs, void *str, int str_len, int alloc);

/*
 * length related
 */
int bstr_avail(bstr_t *bs);
bool bstr_grow(bstr_t *bs, int extra);
bool bstr_setlen(bstr_t *bs, int len);
#define bstr_reset(sb) bstr_setlen(sb, 0)

/*
 * content stuff
 */
bool bstr_addch(bstr_t *bs, uint8_t c);
bool bstr_add(bstr_t *bs, void const *str, int str_len);
bool bstr_addstr(bstr_t *bs, char const *cstr);
bool bstr_addbuf(bstr_t *bs, bstr_t const *bs2);

bool bstr_addf(bstr_t *bs, char const *fmt, ...)
	__attribute__((format(__printf__,2,3)));

bool bstr_eq(bstr_t const *bs1, bstr_t const *bs2);
bool bstr_prefix(bstr_t const *text, bstr_t const *prefix);

/* Find offset of first occurence of a needle in a haystack */
int bstr_find(bstr_t const *hs, bstr_t const *nd);

/* Compare first and last bytes */
static inline bool bstr_first_eq(bstr_t const *bs, uint8_t val)
{
	if (!bs->len)
		return false;
	return (bs->buf[0] == val);
}

static inline bool bstr_last_eq(bstr_t const *bs, uint8_t val)
{
	if (!bs->len)
		return false;
	return (bs->buf[bs->len - 1] == val);
}

/* Drop bytes from the end */
static inline bool bstr_drop_right(bstr_t *bs, uint32_t n)
{
	if ((uint32_t)bs->len < n)
		return false;
	bs->len -= n;
	return true;
}

/* Drop bytes from start of unmanaged buffer */
static inline bool bstr_un_drop_left(bstr_t *bs, uint32_t n)
{
	if ((uint32_t)bs->len < n)
		return false;
	bs->len -= n;
	bs->allocated -= n;
	bs->buf += n;
	return true;
}

/*
 * Parsing / input stuff.
 * These do not guarantee the trailing '\0' terminator.
 */

bool bstr_split_length(bstr_t const *parent, uint32_t len, bstr_t *headp, bstr_t *tailp);

/* Create unmanaged splits across 'parent', head end at terminator */
bool bstr_split_term(bstr_t const *parent, uint8_t terminator, bstr_t *headp, bstr_t *tailp);
bool bstr_split_terms(bstr_t const *parent, bstr_t const *terminators, bstr_t *headp, bstr_t *tailp);
/* Create unmanaged splits across 'parent', tail start after last preceeder */
bool bstr_split_prec(bstr_t const *parent, uint8_t preceeder, bstr_t *headp, bstr_t *tailp);
bool bstr_split_precs(bstr_t const *parent, bstr_t const *preceeders, bstr_t *headp, bstr_t *tailp);

#endif /* __BSTR_H__ */
