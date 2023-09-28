.PHONY: all clean

sources = ../opaque-common/opaque-common.c utils.c
includes = ../opaque-common/opaque-common.h utils.h
libopaque = ../libopaque/src/libopaque.a
objects = ../libopaque/src/common.o ../libopaque/src/opaque.o ../libopaque/src/aux_/kdf_hkdf_sha512.o

all: opaque-server opaque-client

opaque-server: ${sources} ${includes} ${libopaque} opaque-server.c 
	@cc \
		-I . \
		-I ../libopaque/src \
		-I ../opaque-common \
		-L ../libopaque/src \
		-DBENCH \
		-Wall -Wextra -pedantic \
		${sources} \
		$@.c \
		-o $@ \
		-lopaque -lsodium

opaque-client: ${sources} ${includes} ${libopaque} opaque-client.c
	@cc \
		-I . \
		-I ../libopaque/src \
		-I ../opaque-common \
		-L ../libopaque/src \
		-DBENCH \
		-Wall -Wextra -pedantic \
		${sources} \
		$@.c \
		-o $@ \
		-lopaque -lsodium

../libopaque/src/%.o: ../libopaque/src/%.c
	gcc -Wall -c $^ -o $@

../libopaque/src/aux_/kdf_hkdf_sha512.o: ../libopaque/src/aux_/kdf_hkdf_sha512.c
	gcc -Wall -c $^ -o $@

${libopaque}: ${objects}
	ar -rcs $@ $^

clean:
	rm -rf opaque-server opaque-client ../libopaque/src/*.o ../libopaque/src/aux_/*.o
