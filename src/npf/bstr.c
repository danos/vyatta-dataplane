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

#include <stdlib.h>	/* malloc/free/realloc */
#include <string.h>	/* memcpy */
#include <stdio.h>	/* vsnprintf */

#include "bstr.h"

/*
 * Note that the high bit of ->alloc is used to indicate a managed buffer.
 */

#define BSTR_MANAGED(bs)	(!(bs)->allocated || ((bs)->allocated & BSTR_MANAGED_BIT))
#define BSTR_ALLOCATED(bs)	((int)((bs)->allocated & ~BSTR_MANAGED_BIT))

#if BSTR_SMALL
 #define BSTR_MANAGED_BIT	(1 << 15)
 #define BSTR_MAX_ALLOCATED	(INT16_MAX)
 #define BSTR_MAX_LEN		(INT16_MAX - 1)
#else
 #define BSTR_MANAGED_BIT	(1U << 31)
 #define BSTR_MAX_ALLOCATED	(INT32_MAX)
 #define BSTR_MAX_LEN		(INT32_MAX - 1)
#endif /* BSTR_SMALL */

#define VSNPRINTF		vsnprintf


static inline uint8_t ascii_toupper(uint8_t c)
{
	if (c >= 'a' && c <= 'z')
		return c - ('a' - 'A');
	return c;
}

/* Is whitespace? i.e. a space or a tab */
static inline bool ascii_wsp(uint8_t c)
{
	return c == ' ' || c == '\t';
}

/* Is this a CRLF sequence? */
static inline bool ascii_crlf(uint8_t const *p)
{
	return p[0] == '\r' && p[1] == '\n';
}

static inline bool ascii_isalpha(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/*
 * Ensure that ->buf is always non NULL and '\0' terminated.
 */
uint8_t bstr_empty[1];

static void bstr_zinit(struct bstr *bs)
{
	bs->allocated = bs->len = 0;
	bs->buf = bstr_empty;
}

bool bstr_init(struct bstr *bs, int length_hint)
{
	bool rc;

	bstr_zinit(bs);

	rc = length_hint ? bstr_grow(bs, length_hint) : true;

	return rc;
}

void bstr_release(struct bstr *bs)
{
	if (bs->allocated & BSTR_MANAGED_BIT)
		free(bs->buf);

	bstr_zinit(bs);
}

void *bstr_detach(struct bstr *bs, int *length, bool *managed)
{
	uint8_t *cstr;

	cstr = bs->allocated ? bs->buf : NULL;
	if (managed)
		*managed = BSTR_MANAGED(bs) ? true : false;

	if (length)
		*length = bs->len;

	bstr_zinit(bs);

	return cstr;
}

static bool bstr_attach_internal(struct bstr *bs, void *str, int str_len, int allocated)
{
	bstr_release(bs);
	bs->buf = str;
	bs->len = str_len;
	bs->allocated = allocated;
	if (!bstr_grow(bs, 0)) {
		bstr_zinit(bs);
		return false;
	}
	bs->buf[bs->len] = '\0';

	return true;
}

#define ATTACH_INVALID	\
	(str_len > allocated || \
	 str_len > BSTR_MAX_LEN || allocated > BSTR_MAX_ALLOCATED || \
	 str_len < 0 || allocated < 1 || !str)

bool bstr_attach_managed(struct bstr *bs, void *str, int str_len, int allocated)
{
	if (ATTACH_INVALID)
		return false;

	return bstr_attach_internal(bs, str, str_len, allocated | BSTR_MANAGED_BIT);
}

bool bstr_attach_unmanaged(struct bstr *bs, void *str, int str_len, int allocated)
{
	if (ATTACH_INVALID)
		return false;

	return bstr_attach_internal(bs, str, str_len, allocated);
}

int bstr_avail(struct bstr *bs)
{
	int allocated;

	if (!bs->allocated)
		return 0;

	allocated = BSTR_ALLOCATED(bs);

	return (allocated - 1 - bs->len);
}

bool bstr_grow(struct bstr *bs, int extra)
{
	uint8_t *new_str;
	int target, allocated;

	if (extra > BSTR_MAX_ALLOCATED || extra < 0)
		return false;

	target = bs->len + 1 + extra;
	if (target > BSTR_MAX_ALLOCATED)
		return false;

	allocated = BSTR_ALLOCATED(bs);

	/*
	 * Unmanaged must simply compare to the available allocation.
	 * Likewise for a managed and fully allocated string.
	 */
	if (!BSTR_MANAGED(bs) || allocated == BSTR_MAX_ALLOCATED)
		return (target > allocated) ? false : true;

	target += 15;
	target &= ~15;
	if (target > BSTR_MAX_ALLOCATED) {
		target = BSTR_MAX_ALLOCATED;
	}
	new_str = allocated ? realloc(bs->buf, target) : malloc(target);
	if (!new_str)
		return false;

	bs->buf = new_str;
	bs->allocated = target;

	return true;
}

bool bstr_setlen(struct bstr *bs, int len)
{
	if (len > BSTR_MAX_LEN)
		return false;

	if (!bstr_grow(bs, 0))
		return false;

	if (len >= BSTR_ALLOCATED(bs))
		return false;

	bs->len = len;
	bs->buf[len] = '\0';

	return true;
}

bool bstr_addch(struct bstr *bs, uint8_t c)
{
	if (!bstr_grow(bs, 1))
		return false;

	bs->buf[bs->len++] = c;
	bs->buf[bs->len] = '\0';

	return true;
}

bool bstr_add(struct bstr *bs, void const *str, int str_len)
{
	if (!str_len)
		return true;

	if (!bstr_grow(bs, str_len))
		return false;

	memcpy(bs->buf + bs->len, str, str_len);
	return bstr_setlen(bs, bs->len + str_len);
}

bool bstr_addstr(struct bstr *bs, char const *cstr)
{
	return bstr_add(bs, cstr, strlen(cstr));
}

bool bstr_addbuf(struct bstr *bs, struct bstr const *bs2)
{
	return bstr_add(bs, bs2->buf, bs2->len);
}

bool bstr_addf(struct bstr *bs, char const *fmt, ...)
{
	va_list ap;
	char *cp;
	int len;

	/*
	 * First try and fit it in the buffer as is.
	 */
	cp = (char *)bs->buf + bs->len;
	va_start(ap, fmt);
	len = VSNPRINTF(cp, bs->allocated - bs->len, fmt, ap);
	va_end(ap);

	/*
	 * A format error can return zero.
	 */
	if (len < 0 || len + bs->len > BSTR_MAX_LEN)
		return false;

	/*
	 * Try to grow the buffer if it is too small.
	 */
	if (len > bstr_avail(bs)) {
		if (!bstr_grow(bs, len))
			return false;

		cp = (char *)bs->buf + bs->len;
		va_start(ap, fmt);
		len = VSNPRINTF(cp, bs->allocated - bs->len, fmt, ap);
		va_end(ap);

		if (len > bstr_avail(bs))
			return false;
	}

	return (bstr_setlen(bs, bs->len + len));
}

bool bstr_eq(struct bstr const *bs1, struct bstr const *bs2)
{
	if (bs1->len != bs2->len)
		return false;

	return (memcmp(bs1->buf, bs2->buf, bs1->len) == 0);
}

bool bstr_prefix(struct bstr const *text, struct bstr const *prefix)
{
	if (text->len < prefix->len)
		return false;

	return (memcmp(text->buf, prefix->buf, prefix->len) == 0);
}

/*
 * Does the text start with the provided prefix. Performs a byte-by-byte
 * comparison, ignoring the case of the characters.
 */
bool bstr_prefix_ascii_case(struct bstr const *text, struct bstr const *prefix)
{
	int i;

	if (text->len < prefix->len)
		return false;

	for (i = 0; i < prefix->len; i++)
		if (ascii_toupper(text->buf[i]) != ascii_toupper(prefix->buf[i]))
			return false;

	return true;
}

bool bstr_split_length(struct bstr const *parent, uint32_t len,
		       struct bstr *headp, struct bstr *tailp)
{
	uint32_t plen = parent->len;
	uint8_t *pbuf = parent->buf;

	if (len > plen)
		return false;

	/* Block for managed strings */
	if (parent->allocated & BSTR_MANAGED_BIT)
		return false;

	if (len == plen)
		bstr_zinit(tailp);
	else {
		tailp->buf = pbuf + len;
		tailp->allocated = tailp->len = plen - len;
	}

	headp->buf = pbuf;
	headp->allocated = headp->len = len;

	return true;
}

/* split after terminator */
bool bstr_split_term_after(struct bstr const *parent, uint8_t terminator,
			   struct bstr *headp, struct bstr *tailp)
{
	if (!parent->len)
		return false;

	int index = bstr_find_term(parent, terminator);
	if (index < 0)
		return false;

	return bstr_split_length(parent, index + 1, headp, tailp);
}

/* split before terminator */
bool bstr_split_term_before(struct bstr const *parent, uint8_t terminator,
			    struct bstr *headp, struct bstr *tailp)
{
	if (!parent->len)
		return false;

	int index = bstr_find_term(parent, terminator);
	if (index < 0)
		return false;

	return bstr_split_length(parent, index, headp, tailp);
}

bool bstr_split_prec(struct bstr const *parent, uint8_t preceder,
		     struct bstr *headp, struct bstr *tailp)
{
	if (!parent->len)
		return false;

	uint8_t *match = memrchr(parent->buf, preceder, parent->len);
	if (!match)
		return false;

	uint32_t index = match - parent->buf;

	return bstr_split_length(parent, index + 1, headp, tailp);
}

/* Split before first terminating character */
bool bstr_split_terms_before(struct bstr const *parent, struct bstr const *terms,
			     struct bstr *headp, struct bstr *tailp)
{
	if (!parent->len || !terms->len)
		return false;

	int index = bstr_find_terms(parent, terms);
	if (index < 0)
		return false;

	return bstr_split_length(parent, index, headp, tailp);
}

/* Split after first terminating character */
bool bstr_split_terms_after(struct bstr const *parent, struct bstr const *terms,
			    struct bstr *headp, struct bstr *tailp)
{
	if (!parent->len || !terms->len)
		return false;

	int index = bstr_find_terms(parent, terms);
	if (index < 0)
		return false;

	return bstr_split_length(parent, index + 1, headp, tailp);
}

bool bstr_split_after_substr(struct bstr const *parent, struct bstr const *sub,
			     struct bstr *headp, struct bstr *tailp)
{
	int offset = bstr_find_str(parent, sub);

	if (offset < 0)
		return false;

	return bstr_split_length(parent, offset + sub->len, headp, tailp);
}

bool bstr_split_before_substr(struct bstr const *parent, struct bstr const *sub,
			      struct bstr *headp, struct bstr *tailp)
{
	int offset = bstr_find_str(parent, sub);

	if (offset < 0)
		return false;

	return bstr_split_length(parent, offset, headp, tailp);
}

bool bstr_split_precs(struct bstr const *parent, struct bstr const *precs,
		      struct bstr *headp, struct bstr *tailp)
{
	if (!parent->len || !precs->len)
		return false;

	/* Walk along parent, looking for preceeder */
	int const plen = parent->len;
	int const tlen = precs->len;
	uint8_t *pc = parent->buf + plen - 1;
	int pi, ti;

	for (pi = plen - 1; pi >= 0; --pi, --pc) {
		uint8_t *tc = precs->buf;
		for (ti = 0; ti < tlen; ++ti, ++tc) {
			if (*pc == *tc)
				goto found;
		}
	}
	return false;

found:
	return bstr_split_length(parent, pi + 1, headp, tailp);
}

/* Find first non alphabetic ascii character */
static int bstr_find_ascii_non_alpha(struct bstr const *hs)
{
	int const len = hs->len;
	uint8_t *p = hs->buf;
	int i;

	for (i = 0; i < len; ++i, ++p)
		if (!ascii_isalpha(*p))
			return i;

	return -1;
}

/* Split before the first non alphabetic ascii character */
bool bstr_split_ascii_non_alpha_before(struct bstr const *parent,
				       struct bstr *headp, struct bstr *tailp)
{
	int index = bstr_find_ascii_non_alpha(parent);
	if (index < 0)
		return false;

	return bstr_split_length(parent, index, headp, tailp);
}

/* Split after the first non alphabetic ascii character */
bool bstr_split_ascii_non_alpha_after(struct bstr const *parent,
				      struct bstr *headp, struct bstr *tailp)
{
	int index = bstr_find_ascii_non_alpha(parent);
	if (index < 0)
		return false;

	return bstr_split_length(parent, index + 1, headp, tailp);
}

/* Search for string within a string */
static inline int _bstr_find_str(struct bstr const *hs, struct bstr const *nd,
				 uint32_t offs)
{
	uint32_t const hlen = hs->len;
	uint32_t const nlen = nd->len;

	/* Empty needle always matches */
	if (!nlen)
		return 0;

	/* An empty haystack can never match, nor can too big a needle */
	if (offs >= hlen || nlen > (hlen - offs))
		return -1;

	uint8_t *match = memmem(hs->buf + offs, hlen - offs, nd->buf, nlen);
	if (!match)
		return -1;

	return match - hs->buf;
}

/* Search for string within a string */
int bstr_find_str(struct bstr const *hs, struct bstr const *nd)
{
	return _bstr_find_str(hs, nd, 0);
}

/* Search for string within a string, starting at an offset */
int bstr_find_str_offs(struct bstr const *hs, struct bstr const *nd, uint32_t offs)
{
	return _bstr_find_str(hs, nd, offs);
}

/* Walk along parent, looking for one of the terminators */
int bstr_find_terms(struct bstr const *parent, struct bstr const *terms)
{
	int const plen = parent->len;
	int const tlen = terms->len;
	uint8_t *pc = parent->buf;
	int pi, ti;

	for (pi = 0; pi < plen; ++pi, ++pc) {
		uint8_t *tc = terms->buf;
		for (ti = 0; ti < tlen; ++ti, ++tc) {
			if (*pc == *tc)
				return pi;
		}
	}
	return -1;
}

/* Search for a terminating character in a string */
static inline int _bstr_find_term(struct bstr const *parent, uint8_t terminator,
				  uint32_t offs)
{
	if (offs >= (uint32_t)parent->len)
		return -1;

	uint8_t *match = memchr(parent->buf + offs, terminator, parent->len - offs);
	if (!match)
		return -1;

	return match - parent->buf;
}

/* Search for a terminating character in a string */
int bstr_find_term(struct bstr const *parent, uint8_t terminator)
{
	return _bstr_find_term(parent, terminator, 0);
}

/* Search for a terminating character in a string, starting at an offset */
int bstr_find_term_offs(struct bstr const *parent, uint8_t terminator, uint32_t offs)
{
	return _bstr_find_term(parent, terminator, offs);
}

enum bstr_find_wsp {
	WSP,
	NON_WSP,
};

/* Search for next WSP or non-WSP starting at an offset */
static inline int _bstr_find_next_wsp_or_nwsp(struct bstr const *bs,
					      uint32_t offs, enum bstr_find_wsp type)
{
	int const len = bs->len;
	uint8_t *p;
	int i;

	if (offs >= (uint32_t)len)
		return -1;

	for (i = offs, p = bs->buf + offs; i < len; i++, p++)
		if ((type == NON_WSP) ^ ascii_wsp(*p))
			return i;

	return -1;
}

/* Find next whitespace character in a string */
int bstr_find_next_wsp(struct bstr const *bs, uint32_t offs)
{
	return _bstr_find_next_wsp_or_nwsp(bs, offs, WSP);
}

/* Find next non-whitespace character in a string */
int bstr_find_next_non_wsp(struct bstr const *bs, uint32_t offs)
{
	return _bstr_find_next_wsp_or_nwsp(bs, offs, NON_WSP);
}

/*
 * Strip whitespace from the beginning (ltrim), end (rtrim), or both side
 * (trim) of a string.
 *
 * Whitespace (WSP) is defined by ABNF as space and horizontal tab characters
 * (SP / HTAB).
 */
bool bstr_ltrim(struct bstr *bs)
{
	int const len = bs->len;
	uint8_t *p = bs->buf;
	int i;

	if (bs->allocated & BSTR_MANAGED_BIT)
		return false;

	for (i = 0; i < len; i++, p++)
		if (!ascii_wsp(*p))
			return bstr_un_drop_left(bs, i);

	return true;
}

bool bstr_rtrim(struct bstr *bs)
{
	int const len = bs->len;
	uint8_t *p = bs->buf + len - 1;
	int i;

	for (i = 0; i < len; i++, p--)
		if (!ascii_wsp(*p))
			return bstr_drop_right(bs, i);

	return true;
}

bool bstr_trim(struct bstr *bs)
{
	if (!bstr_ltrim(bs))
		return false;

	if (!bstr_rtrim(bs))
		return false;

	return true;
}

/* Is this a CRLF followed by WSP? */
static inline bool ascii_crlf_wsp(uint8_t const *p)
{
	return ascii_crlf(p) && ascii_wsp(*(p+2));
}

/*
 * Trim linear whitespace (LWSP) at start of a string
 *
 * LWSP = *(WSP / CRLF WSP)
 */
bool bstr_lws_ltrim(struct bstr *bs)
{
	int const len = bs->len;
	uint8_t *p = bs->buf;
	int i;

	/* Left-trim not permitted on managed strings */
	if (bs->allocated & BSTR_MANAGED_BIT)
		return false;

	for (i = 0; i < len; i++, p++) {

		if (ascii_wsp(*p))
			continue;

		/*
		 * A CRLF sequence in *only* considered LWS if it is followed
		 * by a SP or a TAB
		 */
		if (i < len - 2 &&  ascii_crlf_wsp(p)) {
			i += 2;
			p += 2;
			continue;
		}
		if (i == 0)
			/* No WSP on left */
			return true;

		/* No more LWSP.  Drop everything to the left of this point */
		return bstr_un_drop_left(bs, i);
	}

	/* string is all whitespace */
	return bstr_un_drop_left(bs, len);

	return true;
}

/* Trim linear whitespace (LWSP) at end of a string */
bool bstr_lws_rtrim(struct bstr *bs)
{
	int const len = bs->len;
	uint8_t *p = bs->buf + len - 1;
	int i;

	/* Simple case.  There is no WSP on the right. */
	if (!ascii_wsp(*p))
		return true;

	for (i = len - 1; i >= 0; i--, p--) {
		/*
		 * A CRLF sequence in only considered LWS if it is followed by
		 * a SP or a TAB
		 */
		if (i >= 2 &&  ascii_crlf_wsp(p-2)) {
			i -= 2;
			p -= 2;
			continue;
		}
		if (ascii_wsp(*p))
			continue;

		/* No more LWSP.  Drop everything after this point */
		return bstr_drop_right(bs, len - i - 1);
	}

	/* string is all whitespace */
	bstr_drop_right(bs, len);

	return true;
}

/* The IPv4 address written to 'addr' is in host byte order */
bool bstr_to_ipaddr(struct bstr const *bs, uint32_t *addr)
{
	uint8_t ip[4];
	int nitems;

	if (bs->len < 7 || bs->len > 15)
		return false;

	nitems = sscanf((const char *)bs->buf, "%hhu.%hhu.%hhu.%hhu",
			&ip[3], &ip[2], &ip[1], &ip[0]);

	if (nitems != 4)
		return false;

	*addr = ip[3] << 24 | ip[2] << 16 | ip[1] << 8 | ip[0];
	return true;
}

/* The port number written to  'port' is in host byte order */
bool bstr_to_port(struct bstr const *bs, uint16_t *port)
{
	if (bs->len < 1 || bs->len > 5)
		return false;

	return sscanf((const char *)bs->buf, "%hu", port) == 1;
}

/* Simple bstr hash */
uint32_t bstr_hash(struct bstr const *bs, uint32_t const initval)
{
	uint8_t const shift[4] = {0, 8, 16, 24};
	uint32_t hash = initval;
	int const len = bs->len;
	uint8_t *p = bs->buf;
	int i;

	for (i = 0; i < len; i++, p++)
		hash ^= (*p << shift[i & 0x3]);

	return hash;
}
