/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Copyright 2010, Derek Fawcus.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef BSTR_H
#define BSTR_H

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
 * The code always ensures that once initialised (either by the static
 * initialiser BSTR_INIT,  or via calling bstr_init()),  the
 * string will always be '\0' terminated,  and that the ->buf element
 * will be valid.  Hence maintaining easy of use and compatibility
 * with generic 'c strings'.
 *
 * Example use of dynamic string (error checking omitted):
 * @code
 * void foo (ptr_t *ptr)
 * {
 *     struct bstr sb;
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
 *     struct bstr sb = BSTR_INIT;
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
 *
 * Assumptions
 *
 * 1. The bstr 'buf' pointer in an unmanaged string is always expeced to be non-NULL
 * 2. The bstr_split_x are not used for managed strings
 *
 * Thread Safety
 *
 * It is not expected that these routines will be used for manipulating the
 * same instance of a bstr from more than one thread concurrently. That is not
 * their use case.
 *
 * The output routines using managed buffers are not thread safe if the
 * malloc/free implementation is not safe.  Managed buffers automatically
 * grow, and one has to explicitly release the object. So they follow a
 * malloc/free type of pattern.
 *
 * The unmanaged routines are safe. The unmanaged string forms were intended
 * for use as stack allocated variables, and so vanish the same way as any
 * other auto variables vanish, and pointers to such becoming invalid.
 *
 * For the unmanaged strings, the buffer is expected to be fixed somewhere,
 * can not grow, and it allows for automatic deallocation as one is using
 * entirely stack based stuff. i.e. one does not have to follow the
 * malloc/free pattern.
 *
 * So one can have an on-stack backing buffer (of fixed size), and a struct
 * bstr on stack using it. Once the functions return, everything is cleaned
 * up. If one chooses to malloc the buffer for an unmanaged buffer, then one
 * is responsible for eventually freeing that buffer.
 *
 * If unmanaged bstrs and their backing buffer are *not* stack varables then
 * it is up to the user to ensure correct and safe useage.
 *
 *
 * Unmanaged Strings Use-case
 *
 * One or more bstrs will be used to reference the payload of *coalesced*
 * packet buffers (rte_mbuf).  These bstrs will be local variables, so the
 * view over the buffer will be automatically cleaned up when the function
 * returns.
 *
 * Alternatively, the bstrs may be in a per-core packet cache, and as such
 * will only be valid for the duration of the packet.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/**
 * Adjust to control maximum capacity of strings.
 */
#define BSTR_SMALL 0

/**
 * One should not access the ->allocated member as its encoding is private.
 * The buf and len members may be accessed.
 *
 * Hence this is a semi-opaque struct.
 *
 * The buf pointer is always expected to be non-NULL.
 */
#if BSTR_SMALL
struct bstr {
	uint8_t *buf;
	int16_t len;
	uint16_t allocated;
};
#else
struct bstr {
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
#define BSTR_INIT (struct bstr){bstr_empty, 0, 0}

/*
 * Useful for constants in array / structure definitions.
 */
#define BSTR_K(str) {.buf = (uint8_t *)(str), .len = sizeof(str) - 1, .allocated = sizeof(str)}

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
#define BSTRL_GCC(str) ({static const uint8_t _bc[] = (str); \
			static const struct bstr _bb = BSTR_K(_bc); &_bb; })
#define BSTRL_STANDARD(str) (&(const struct bstr)BSTR_K(str))

/* A Literal string */
#ifdef __GNUC__
 #define BSTRL(str) BSTRL_GCC(str)
#else
 #define BSTRL(str) BSTRL_STANDARD(str)
#endif /* __GNUC__ */

/*
 * create/destroy/management
 */

/* Initialise to empty string, with initial capacity for length */
bool bstr_init(struct bstr *bs, int length_hint);

/* Free any existing backing store, and reinitialise to empty string */
void bstr_release(struct bstr *bs);

/* Extract backing buffer and length from a passed in string */
void *bstr_detach(struct bstr *bs, int *length, bool *managed);

/* Attach a malloc'ed backing buffer to a dynamic string. Freed by bstr_release() */
bool bstr_attach_managed(struct bstr *bs, void *str, int str_len, int alloc);

/* Attach a backing buffer to a static string. Caller responsible for freeing */
bool bstr_attach_unmanaged(struct bstr *bs, void *str, int str_len, int alloc);

/*
 * length related
 */

/* How much available (unused) space does a string have */
int bstr_avail(struct bstr *bs);

/* Ensure that a string has space for extra bytes; if dynamic possibly reallocate backing buffer */
bool bstr_grow(struct bstr *bs, int extra);

/* Set the length of the string, not altering its contents, but terminating at the length */
bool bstr_setlen(struct bstr *bs, int len);

/* Set the string to zero length */
#define bstr_reset(sb) bstr_setlen(sb, 0)

/*
 * content stuff
 */

/* Add a single byte to the end */
bool bstr_addch(struct bstr *bs, uint8_t c);

/* Add str_len bytes pointed to by str */
bool bstr_add(struct bstr *bs, void const *str, int str_len);

/* Add bytes from a NULL terminated c-string to a string (c.f. strcat) */
bool bstr_addstr(struct bstr *bs, char const *cstr);

/* Add bytes from one string to end of another (c.f. strcat) */
bool bstr_addbuf(struct bstr *bs, struct bstr const *bs2);

/* Add formatted bytes to a string (c.f. snprint) */
bool bstr_addf(struct bstr *bs, char const *fmt, ...)
	__attribute__((format(__printf__, 2, 3)));

/* Are the two strings identical */
bool bstr_eq(struct bstr const *bs1, struct bstr const *bs2);

/* Does the text start with the provided prefix */
bool bstr_prefix(struct bstr const *text, struct bstr const *prefix);

/* Find offset of first occurrence of a needle in a haystack (c.f. strstr) */
int bstr_find_str(struct bstr const *hs, struct bstr const *nd);

int bstr_find_term(struct bstr const *parent, uint8_t terminator);

/* Does the string start with this character */
static inline bool bstr_first_eq(struct bstr const *bs, uint8_t val)
{
	if (!bs->len)
		return false;
	return (bs->buf[0] == val);
}

/* Does the string end with this character */
static inline bool bstr_last_eq(struct bstr const *bs, uint8_t val)
{
	if (!bs->len)
		return false;
	return (bs->buf[bs->len - 1] == val);
}

/* Does the penultimate byte match val? */
static inline bool bstr_penultimate_eq(struct bstr const *text, uint8_t val)
{
	return text->len >= 2 && text->buf[text->len - 2] == val;
}

/* Drop bytes from the end */
static inline bool bstr_drop_right(struct bstr *bs, uint32_t n)
{
	if ((uint32_t)bs->len < n)
		return false;
	bs->len -= n;
	return true;
}

/* Drop bytes from start of unmanaged buffer */
static inline bool bstr_un_drop_left(struct bstr *bs, uint32_t n)
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

/* Initialise two sub-strings (slices) over the parent; head being len bytes, tail the rest */
bool bstr_split_length(struct bstr const *parent, uint32_t len,
		       struct bstr *headp, struct bstr *tailp);

/* Create unmanaged splits across 'parent', head end at terminator */

/* Initialise two sub-strings (slices) over the parent at the matching terminator, if found */
bool bstr_split_term(struct bstr const *parent, uint8_t terminator,
		     struct bstr *headp, struct bstr *tailp);

/* bstr_split_term() for the first matching terminator */
bool bstr_split_terms(struct bstr const *parent, struct bstr const *terminators,
		      struct bstr *headp, struct bstr *tailp);

/* Create unmanaged splits across 'parent', tail start after last preceeder */

/* Akin to strrchr() - split_term() from end of string */
bool bstr_split_prec(struct bstr const *parent, uint8_t preceder,
		     struct bstr *headp, struct bstr *tailp);

/* Akin to strtok() backwards; split_terms() from end of string */
bool bstr_split_precs(struct bstr const *parent, struct bstr const *preceders,
		      struct bstr *headp, struct bstr *tailp);

bool bstr_split_after_substr(struct bstr const *parent, struct bstr const *sub,
			     struct bstr *headp, struct bstr *tailp);

bool bstr_split_before_substr(struct bstr const *parent, struct bstr const *sub,
			      struct bstr *headp, struct bstr *tailp);

#endif /* BSTR_H */
