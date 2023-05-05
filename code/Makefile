
.PHONY: main bench clean

BITS?=512

ifndef UINT_IMPL
	UINT_IMPL=uint.c
	ifneq ("$(wildcard p${BITS}/uint.s)", "")
		UINT_IMPL=$(wildcard p${BITS}/uint.*)
	endif
endif

ifndef FP_IMPL
	FP_IMPL=fp.c
	ifneq ("$(wildcard p${BITS}/fp.s)", "")
		FP_IMPL=$(wildcard p${BITS}/fp.*)
	endif
	FP_IMPL+=$(wildcard p${BITS}/inv/*.c p${BITS}/inv/*.s)
endif


sources = p${BITS}/constants.c
sources += rng.c
sources += ${UINT_IMPL} ${FP_IMPL}
sources += mont.c
sources += csidh.c

includes = $(wildcard *.h p${BITS}/*.h)

.PHONY : all
all : opus updatable prf networked

networked: server client
	
server: ${includes} ${sources} server.c
	@cc \
		$(if ${BENCH_ITS},-DBENCH_ITS=${BENCH_ITS}) \
		$(if ${BENCH_VERBOSE},-DBENCH_VERBOSE=${BENCH_VERBOSE}) \
		-I ./ \
		-I p${BITS}/ \
		-std=c99 -pedantic \
		-Wall -Wextra \
		-march=native -O3 \
		-funroll-loops \
		-DNDEBUG \
		-pthread\
		$(sources) \
		server.c \
		-o server

client: ${includes} ${sources} client.c
	@cc \
		$(if ${BENCH_ITS},-DBENCH_ITS=${BENCH_ITS}) \
		$(if ${BENCH_VERBOSE},-DBENCH_VERBOSE=${BENCH_VERBOSE}) \
		-I ./ \
		-I p${BITS}/ \
		-std=gnu99 -pedantic \
		-Wall -Wextra \
		-march=native -O3 \
		-funroll-loops \
		-DNDEBUG \
		-pthread -lrt \
		$(sources) \
		client.c \
		-o client

prf: ${includes} ${sources} prf.c
	@cc \
		$(if ${BENCH_ITS},-DBENCH_ITS=${BENCH_ITS}) \
		$(if ${BENCH_VERBOSE},-DBENCH_VERBOSE=${BENCH_VERBOSE}) \
		-I ./ \
		-I p${BITS}/ \
		-std=c99 -pedantic \
		-Wall -Wextra \
		-march=native -O3 \
		-DNDEBUG \
		$(sources) \
		prf.c \
		-o prf

opus: ${includes} ${sources} opus.c
	@cc \
		$(if ${BENCH_ITS},-DBENCH_ITS=${BENCH_ITS}) \
		$(if ${BENCH_VERBOSE},-DBENCH_VERBOSE=${BENCH_VERBOSE}) \
		-I ./ \
		-I p${BITS}/ \
		-std=c99 -pedantic \
		-Wall -Wextra \
		-march=native -O3 \
		-funroll-loops \
		-DNDEBUG \
		$(sources) \
		opus.c \
		-o opus
updatable: ${includes} ${sources} updatable.c
	@cc \
		$(if ${BENCH_ITS},-DBENCH_ITS=${BENCH_ITS}) \
		$(if ${BENCH_VERBOSE},-DBENCH_VERBOSE=${BENCH_VERBOSE}) \
		-I ./ \
		-I p${BITS}/ \
		-std=c99 -pedantic \
		-Wall -Wextra \
		-march=native -O3 \
		-DNDEBUG \
		$(sources) \
		updatable.c \
		-o updatable
clean:
	@rm -f prf opus updatable server client

