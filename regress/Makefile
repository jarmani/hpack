HPACKSRCDIR=		${.CURDIR}/..
HPACKTESTDIR+=		${.CURDIR}/hpack-test-samples
HPACKTESTDIR+=		${.CURDIR}/hpack-test-case

.PATH:	${HPACKSRCDIR}

PROG=			hpacktest
SRCS+=			main.c jsmn.c json.c
CFLAGS+=		-DJSMN_PARENT_LINKS

REGRESS_TARGETS?=	test run-rfc7541 run-fixes

test: ${PROG}
	./${PROG} -v ${HPACKTESTDIR}

# Decode the examples of RFC 7541 Appendix C and the tests for fixed bugs,
# and encode the header lists again.
CLEANFILES+=		hpackvectors

hpackvectors: hpackvectors.c hpack.c
	${CC} ${CFLAGS} -o $@ ${.ALLSRC}

run-rfc7541: hpackvectors
	./hpackvectors ${.CURDIR}/rfc7541.vectors

run-fixes: hpackvectors
	./hpackvectors ${.CURDIR}/fixes.vectors

.include <bsd.regress.mk>
