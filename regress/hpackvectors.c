/*	$OpenBSD$	*/

/*
 * Copyright (c) 2026 Jonathan Armani <armani@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Test the HPACK library.  The vectors file holds the
 * examples of RFC 7541 Appendix C: each header block is decoded with
 * a new or the previous dynamic table and compared with the expected
 * header list and table size.  The expected header lists are also
 * encoded and decoded again to test the encoder.
 */

#include <sys/types.h>
#include <sys/queue.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hpack.h"

struct vector {
	char				 name[64];
	size_t				 table_max;
	int				 keep;
	unsigned char			*block;
	size_t				 blocklen;
	struct hpack_headerblock	*hdrs;
	size_t				 size;
	int				 expect_fail;
};

static int	 failed;

static void
fail(const struct vector *v, const char *fmt, const char *a, const char *b)
{
	printf("FAIL %s: ", v->name);
	printf(fmt, a, b);
	printf("\n");
	failed++;
}

static unsigned char *
unhex(const char *s, size_t *len)
{
	unsigned char	*buf;
	size_t		 i, n = strlen(s) / 2;
	unsigned int	 c;

	if ((buf = calloc(1, n + 1)) == NULL)
		err(1, NULL);
	for (i = 0; i < n; i++) {
		if (sscanf(s + 2 * i, "%2x", &c) != 1)
			errx(1, "bad hex: %s", s);
		buf[i] = c;
	}
	*len = n;
	return (buf);
}

/* Compare two header lists, names and values must match in order */
static int
compare(const struct vector *v, const char *what,
    struct hpack_headerblock *a, struct hpack_headerblock *b)
{
	struct hpack_header	*ha, *hb;

	for (ha = TAILQ_FIRST(a), hb = TAILQ_FIRST(b);
	    ha != NULL && hb != NULL;
	    ha = TAILQ_NEXT(ha, hdr_entry), hb = TAILQ_NEXT(hb, hdr_entry)) {
		if (strcmp(ha->hdr_name, hb->hdr_name) != 0 ||
		    strcmp(ha->hdr_value, hb->hdr_value) != 0) {
			fail(v, "%s: header %s", what, ha->hdr_name);
			return (-1);
		}
	}
	if (ha != NULL || hb != NULL) {
		fail(v, "%s: %s", what, "number of headers");
		return (-1);
	}
	return (0);
}

static void
test_vector(const struct vector *v, struct hpack_table **dec,
    struct hpack_table **enc, struct hpack_table **rdec)
{
	struct hpack_headerblock	*hdrs, *rhdrs;
	unsigned char			*buf;
	size_t				 len;
	char				 sz[32];
	int				 before = failed;

	if (!v->keep || *dec == NULL) {
		hpack_table_free(*dec);
		hpack_table_free(*enc);
		hpack_table_free(*rdec);
		if ((*dec = hpack_table_new(v->table_max)) == NULL ||
		    (*enc = hpack_table_new(v->table_max)) == NULL ||
		    (*rdec = hpack_table_new(v->table_max)) == NULL)
			err(1, NULL);
	}

	/* An invalid header block must be rejected */
	if (v->expect_fail) {
		if ((hdrs = hpack_decode(v->block, v->blocklen,
		    *dec)) != NULL) {
			fail(v, "%s%s", "invalid block was decoded", "");
			hpack_headerblock_free(hdrs);
		} else
			printf("ok %s\n", v->name);
		return;
	}

	/* Decode the example, a vector without block is only encoded */
	if (v->block != NULL) {
		if ((hdrs = hpack_decode(v->block, v->blocklen,
		    *dec)) == NULL) {
			fail(v, "%s%s", "decode failed", "");
			return;
		}
		if (compare(v, "decode", hdrs, v->hdrs) == 0 &&
		    hpack_table_size(*dec) != v->size) {
			snprintf(sz, sizeof(sz), "%zu",
			    hpack_table_size(*dec));
			fail(v, "decode: table size %s%s", sz, "");
		}
		hpack_headerblock_free(hdrs);
	}

	/* Encode the expected list and decode it again */
	if ((buf = hpack_encode(v->hdrs, &len, *enc)) == NULL) {
		fail(v, "%s%s", "encode failed", "");
		return;
	}
	if ((rhdrs = hpack_decode(buf, len, *rdec)) == NULL)
		fail(v, "%s%s", "decode of encoded block failed", "");
	else
		compare(v, "round trip", rhdrs, v->hdrs);
	hpack_headerblock_free(rhdrs);
	free(buf);

	if (failed == before)
		printf("ok %s\n", v->name);
}

int
main(int argc, char *argv[])
{
	struct hpack_table	*dec = NULL, *enc = NULL, *rdec = NULL;
	struct vector		 v;
	FILE			*fp;
	char			*line = NULL, *p, *name;
	size_t			 linesize = 0;
	ssize_t			 linelen;
	int			 n = 0;

	if (argc != 2)
		errx(1, "usage: hpackvectors vectors");
	if (hpack_init() == -1)
		errx(1, "hpack_init");
	if ((fp = fopen(argv[1], "r")) == NULL)
		err(1, "%s", argv[1]);

	memset(&v, 0, sizeof(v));
	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		line[strcspn(line, "\n")] = '\0';
		if (strncmp(line, "# RFC 7541 ", 11) == 0) {
			strlcpy(v.name, line + 11, sizeof(v.name));
		} else if (strncmp(line, "# test ", 7) == 0) {
			strlcpy(v.name, line + 7, sizeof(v.name));
		} else if (strcmp(line, "fail") == 0) {
			v.expect_fail = 1;
		} else if (strncmp(line, "table ", 6) == 0) {
			v.table_max = strtoul(line + 6, &p, 10);
			v.keep = strcmp(p, " keep") == 0;
			if ((v.hdrs = hpack_headerblock_new()) == NULL)
				err(1, NULL);
		} else if (strncmp(line, "hex ", 4) == 0) {
			v.block = unhex(line + 4, &v.blocklen);
		} else if (strncmp(line, "header ", 7) == 0) {
			name = line + 7;
			if ((p = strchr(name, ' ')) == NULL)
				errx(1, "bad header: %s", line);
			*p++ = '\0';
			if (hpack_header_add(v.hdrs, name, p,
			    HPACK_INDEX) == NULL)
				err(1, NULL);
		} else if (strncmp(line, "size ", 5) == 0) {
			v.size = strtoul(line + 5, NULL, 10);
		} else if (strcmp(line, "end") == 0) {
			test_vector(&v, &dec, &enc, &rdec);
			hpack_headerblock_free(v.hdrs);
			free(v.block);
			memset(&v, 0, sizeof(v));
			n++;
		}
	}
	free(line);
	fclose(fp);
	hpack_table_free(dec);
	hpack_table_free(enc);
	hpack_table_free(rdec);

	printf("%d vectors, %d failed\n", n, failed);
	return (failed ? 1 : 0);
}
