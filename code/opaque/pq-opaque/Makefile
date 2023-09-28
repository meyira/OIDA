.PHONY : all opaque bench clean

BITS?=512
csifish=../CSI-FiSh/implementation
nroprf = ../nr-oprf/build
libkeccak = ${csifish}/XKCP/bin/generic64/libkeccak.a
libnroprf = ${nroprf}/libnr-oprf.so
CFLAGS = -std=c99 -pedantic -Wall -Wextra -march=native -O3 -funroll-loops -g

ifndef UINT_IMPL
	UINT_IMPL=uint.c
	ifneq ("$(wildcard ${csifish}/p${BITS}/uint.s)", "")
		UINT_IMPL=$(wildcard ${csifish}/p${BITS}/uint.*)
	endif
endif

ifndef FP_IMPL
	FP_IMPL=fp.c
	ifneq ("$(wildcard ${csifish}/p${BITS}/fp.s)", "")
		FP_IMPL=$(wildcard ${csifish}/p${BITS}/fp.*)
	endif
	FP_IMPL+=$(wildcard ${csifish}/p${BITS}/inv/*.c ${csifish}/p${BITS}/inv/*.s)
endif


sources = ${csifish}/p${BITS}/constants.c ${csifish}/classgroup.c ${csifish}/csidh.c 
sources += ${csifish}/csifish.c ${csifish}/merkletree.c ${csifish}/mont.c ${csifish}/reduce.c
sources += ${csifish}/rng.c
sources += ${UINT_IMPL} ${FP_IMPL}
sources += ../libopaque/src/aux_/kdf_hkdf_sha512.c
sources += ../opus/opus.c
sources += ../csike/csike.c
sources += ../opaque-common/opaque-common.c
sources += utils.c

includes = $(wildcard ${csifish}/*.h ${csifish}/p${BITS}/*.h ../opus/*.h ../csike/csike.h utils.h)

all : opaque benchmark
	
opaque: opaque-server opaque-client opaque-server-nroprf opaque-client-nroprf

opaque-server: ${includes} ${sources} ${libkeccak} opaque-server.c
	@cc \
		-I . \
		-I ${csifish} \
		-I ${csifish}/p${BITS} \
		-I ${csifish}/XKCP/bin/generic64 \
		-I ../libopaque/src/ \
		-I ../opus/ \
		-I ../csike \
		-I ../opaque-common \
		-L ${csifish}/XKCP/bin/generic64 \
		-DBENCH \
		${CFLAGS} \
		$(sources) \
		$@.c \
		-o $@ \
		-lsodium -lm -lgmp -lcrypto -lkeccak 

opaque-client: ${includes} ${sources} ${libkeccak} opaque-client.c
	@cc \
		-I . \
		-I ${csifish} \
		-I ${csifish}/p${BITS} \
		-I ${csifish}/XKCP/bin/generic64 \
		-I ../libopaque/src/ \
		-I ../opus/ \
		-I ../csike \
		-I ../opaque-common \
		-L ${csifish}/XKCP/bin/generic64 \
		-DBENCH \
		${CFLAGS} \
		$(sources) \
		$@.c \
		-o $@ \
		-lsodium -lm -lgmp -lcrypto -lkeccak 

opaque-server-nroprf: ${includes} ${sources} ${libkeccak} ${libnroprf} opaque-server.c
	@cc \
		-I . \
		-I ${csifish} \
		-I ${csifish}/p${BITS} \
		-I ${csifish}/XKCP/bin/generic64 \
		-I ../libopaque/src/ \
		-I ../opus/ \
		-I ../csike \
		-I ../opaque-common \
		-L ${csifish}/XKCP/bin/generic64 \
		-L ${nroprf} \
		-Wl,-rpath ${nroprf} \
		-DBENCH \
		-DNR_OPRF \
		${CFLAGS} \
		$(sources) \
		opaque-server.c \
		-o $@ \
		-lsodium -lm -lgmp -lcrypto -lkeccak -lnr-oprf
	
opaque-client-nroprf: ${includes} ${sources} ${libkeccak} ${libnroprf} opaque-client.c
	@cc \
		-I . \
		-I ${csifish} \
		-I ${csifish}/p${BITS} \
		-I ${csifish}/XKCP/bin/generic64 \
		-I ../libopaque/src/ \
		-I ../opus/ \
		-I ../csike \
		-I ../opaque-common \
		-L ${csifish}/XKCP/bin/generic64 \
		-L ${nroprf} \
		-Wl,-rpath ${nroprf} \
		-DBENCH \
		-DNR_OPRF \
		${CFLAGS} \
		$(sources) \
		opaque-client.c \
		-o $@ \
		-lsodium -lm -lgmp -lcrypto -lkeccak -lnr-oprf
		
benchmark: ${includes} ${sources} ${libkeccak} benchmark.c
	@cc \
		-I . \
		-I ${csifish} \
		-I ${csifish}/p${BITS} \
		-I ${csifish}/XKCP/bin/generic64 \
		-I ../libopaque/src/ \
		-I ../opus/ \
		-I ../csike/ \
		-I ../opaque-common \
		-L ${csifish}/XKCP/bin/generic64 \
		-DBENCH \
		${CFLAGS} \
		${sources} \
		$@.c \
		-o $@ \
		-lsodium -lm -lgmp -lcrypto -lkeccak 

${libkeccak}:
	cd ${csifish}/XKCP && \
	make generic64/libkeccak.a

${libnroprf}:
	cd ../nr-oprf && \
	mkdir build && \
	cd build && \
	cmake .. && \
	make

clean:
	@rm -f opaque-client opaque-server opaque-client-nroprf opaque-server-nroprf benchmark

