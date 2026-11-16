hpack
=====

HPACK ([RFC 7541][1]) header compression for HTTP/2, written in C, with the
[hpack(3)](hpack.md) API.

The library is a single `hpack.c` and `hpack.h` in OpenBSD style. It is careful
with input and output buffers and uses heap allocations instead of stack
buffers.

hpack was written by Reyk Floeter, who no longer works on it. This fork is a
first step for OpenBSD HTTP/2 support [httpd(8)][2].

Changes since the original
--------------------------

Each fix comes with a regress test:

- never indexed literals were not decoded
- integers were not bounded and reads could go past the data
- Huffman padding was not checked and EOS was accepted in a string
- NUL in a string literal truncated the header name or value
- table size updates were accepted in the middle of a header block
- integers of the size of the prefix were encoded wrong
- header values were matched case-insensitively by the encoder
- memory leaks, and errx() calls in library code

There are also new tests with the examples of RFC 7541 and a decoder fuzzer.

Building and testing
--------------------

The library and its tests build on OpenBSD:

```
$ git submodule update --init
$ make
$ make regress
```

The regress targets are:

- `test`: decode the [hpack-test-case][3] stories and the samples in
  `regress/hpack-test-samples`
- `run-rfc7541`: decode the examples of RFC 7541 Appendix C and encode the
  header lists again
- `run-fixes`: the tests of the fixed bugs
- `run-fuzz`: fuzz the decoder with a fixed seed, set `FUZZ_ITERATIONS` for a
  longer run

TODO
----

- fuzz the encoder too, and run the fuzzer longer
- indexing heuristics for encoders that keep a dynamic table: don't index values
  that change with every message and never index sensitive headers

License
-------

ISC, see the header of each file.

[1]: https://www.rfc-editor.org/rfc/rfc7541
[2]: https://man.openbsd.org/httpd.8
[3]: https://github.com/http2jp/hpack-test-case
