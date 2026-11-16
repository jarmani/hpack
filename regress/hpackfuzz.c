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
 * Mutational fuzzer for the HPACK decoder.  Header blocks
 * are generated to stress integer prefixes, Huffman strings and
 * dynamic table size updates, or mutated from the RFC 7541 examples,
 * and decoded with a persistent dynamic table.  Each input is written
 * to the file "current" before it is decoded, so a crash leaves the
 * input behind.  Invariants are checked after each decode.
 *
 * usage: hpackfuzz [-n iterations] [-s seed] vectors
 */

#include <sys/types.h>
#include <sys/queue.h>

#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hpack.h"

#define MAXSEEDS	64
#define MAXBLOCK	4096

static unsigned char	*seeds[MAXSEEDS];
static size_t		 seedlen[MAXSEEDS];
static int		 nseeds;
static uint64_t		 rnd_state;

/* Deterministic PRNG (splitmix64) so that runs can be reproduced */
static uint32_t
rnd(uint32_t n)
{
	uint64_t	 z;

	z = (rnd_state += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	z ^= z >> 31;
	return (n == 0 ? (uint32_t)z : (uint32_t)(z % n));
}

static void
load_seeds(const char *file)
{
	FILE		*fp;
	char		*line = NULL;
	size_t		 linesize = 0, i, n;
	unsigned int	 c;

	if ((fp = fopen(file, "r")) == NULL)
		err(1, "%s", file);
	while (getline(&line, &linesize, fp) != -1 && nseeds < MAXSEEDS) {
		if (strncmp(line, "hex ", 4) != 0)
			continue;
		line[strcspn(line, "\n")] = '\0';
		n = strlen(line + 4) / 2;
		if ((seeds[nseeds] = malloc(n)) == NULL)
			err(1, NULL);
		for (i = 0; i < n; i++) {
			sscanf(line + 4 + 2 * i, "%2x", &c);
			seeds[nseeds][i] = c;
		}
		seedlen[nseeds++] = n;
	}
	free(line);
	fclose(fp);
}

/* An integer with the given prefix, optionally over-long */
static size_t
gen_int(unsigned char *p, unsigned char flag, unsigned char mask)
{
	size_t	 len = 1, i, n;

	switch (rnd(4)) {
	case 0:		/* small value inside the prefix */
		p[0] = flag | (rnd(256) & ~mask);
		break;
	case 1:		/* prefix boundary: value == 2^N - 1, then 0 */
		p[0] = flag | (~mask & 0xff);
		p[len++] = rnd(2) ? 0x00 : (rnd(128));
		break;
	default:	/* long continuation, possibly unterminated */
		p[0] = flag | (~mask & 0xff);
		n = 1 + rnd(20);
		for (i = 0; i < n; i++)
			p[len++] = 0x80 | rnd(128);
		if (rnd(4))
			p[len++] = rnd(128);
		break;
	}
	return (len);
}

/* A string literal, raw or "Huffman" with random bits */
static size_t
gen_str(unsigned char *p, size_t room)
{
	size_t	 n = rnd(40), len = 0, i;

	if (n + 2 > room)
		n = 0;
	p[len++] = (rnd(2) ? 0x80 : 0x00) | n;
	for (i = 0; i < n; i++)
		p[len++] = rnd(4) ? rnd(256) : 0xff;	/* EOS-ish padding */
	return (len);
}

static size_t
generate(unsigned char *p)
{
	size_t	 len = 0;
	int	 i, n = 1 + rnd(12);

	for (i = 0; i < n && len < MAXBLOCK - 128; i++) {
		switch (rnd(6)) {
		case 0:		/* 6.1 indexed */
			len += gen_int(p + len, 0x80, 0x80);
			break;
		case 1:		/* 6.2.1 incremental indexing, new name */
			p[len++] = 0x40;
			len += gen_str(p + len, MAXBLOCK - len);
			len += gen_str(p + len, MAXBLOCK - len);
			break;
		case 2:		/* 6.2.1 with indexed name */
			len += gen_int(p + len, 0x40, 0xc0);
			len += gen_str(p + len, MAXBLOCK - len);
			break;
		case 3:		/* 6.2.2 / 6.2.3 */
			len += gen_int(p + len, rnd(2) ? 0x10 : 0x00, 0xf0);
			len += gen_str(p + len, MAXBLOCK - len);
			break;
		case 4:		/* 6.3 dynamic table size update */
			len += gen_int(p + len, 0x20, 0xe0);
			break;
		default:	/* garbage */
			p[len++] = rnd(256);
			break;
		}
	}
	return (len);
}

static size_t
mutate(unsigned char *p)
{
	size_t	 len, i, n, pos;
	int	 s = rnd(nseeds);

	len = seedlen[s];
	memcpy(p, seeds[s], len);
	n = 1 + rnd(8);
	for (i = 0; i < n && len > 0; i++) {
		pos = rnd(len);
		switch (rnd(5)) {
		case 0:		/* bit flip */
			p[pos] ^= 1 << rnd(8);
			break;
		case 1:		/* random byte */
			p[pos] = rnd(256);
			break;
		case 2:		/* insert */
			if (len < MAXBLOCK) {
				memmove(p + pos + 1, p + pos, len - pos);
				p[pos] = rnd(256);
				len++;
			}
			break;
		case 3:		/* delete */
			memmove(p + pos, p + pos + 1, len - pos - 1);
			len--;
			break;
		default:	/* truncate */
			len = pos;
			break;
		}
	}
	return (len);
}

/* Invariants of a decoded header block and the dynamic table */
static void
check(struct hpack_headerblock *hdrs, struct hpack_table *tbl,
    size_t max)
{
	struct hpack_header	*hdr;

	if (hpack_table_size(tbl) > max)
		errx(2, "table size %zu > max %zu", hpack_table_size(tbl),
		    max);
	if (hdrs == NULL)
		return;
	TAILQ_FOREACH(hdr, hdrs, hdr_entry) {
		if (hdr->hdr_name == NULL || hdr->hdr_value == NULL)
			errx(2, "header without name or value");
		(void)strlen(hdr->hdr_name);
		(void)strlen(hdr->hdr_value);
	}
}

int
main(int argc, char *argv[])
{
	struct hpack_headerblock	*hdrs;
	struct hpack_table		*tbl = NULL;
	unsigned char			 buf[MAXBLOCK + 1];
	unsigned long			 i, iterations = 100000;
	unsigned long			 decoded = 0;
	size_t				 len, max = 4096;
	int				 ch, fd;
	const char			*errstr;

	rnd_state = 1;
	while ((ch = getopt(argc, argv, "n:s:")) != -1) {
		switch (ch) {
		case 'n':
			iterations = strtonum(optarg, 1, LLONG_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "iterations %s", errstr);
			break;
		case 's':
			rnd_state = strtonum(optarg, 0, LLONG_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "seed %s", errstr);
			break;
		default:
			errx(1, "usage: hpackfuzz [-n iter] [-s seed] vectors");
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		errx(1, "usage: hpackfuzz [-n iter] [-s seed] vectors");

	if (hpack_init() == -1)
		errx(1, "hpack_init");
	load_seeds(argv[0]);
	if (nseeds == 0)
		errx(1, "no seeds");
	if ((fd = open("current", O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		err(1, "current");

	for (i = 0; i < iterations; i++) {
		/* A new table with a random size now and then */
		if (tbl == NULL || rnd(1000) == 0) {
			hpack_table_free(tbl);
			max = rnd(4) ? 4096 : rnd(8192);
			if ((tbl = hpack_table_new(max)) == NULL)
				err(1, NULL);
			if (max == 0)
				max = 4096;	/* 0 selects the default */
		}
		len = rnd(2) ? generate(buf) : mutate(buf);
		if (pwrite(fd, buf, len, 0) == -1 || ftruncate(fd, len) == -1)
			err(1, "current");
		hdrs = hpack_decode(buf, len, tbl);
		if (hdrs != NULL)
			decoded++;
		check(hdrs, tbl, max);
		hpack_headerblock_free(hdrs);
	}
	hpack_table_free(tbl);
	close(fd);
	printf("%lu iterations, %lu decoded, no crash\n", iterations,
	    decoded);
	return (0);
}
