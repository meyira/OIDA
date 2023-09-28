.PHONY: all clean

sources = main.c
sources += csike.c
sources += ../csidh/p512/constants.c
sources += ../csidh/rng.c
sources += ../csidh/p512/uint.s ../csidh/p512/fp.s
sources += $(wildcard ../csidh/p512/inv/*.c ../csidh/p512/inv/*.s)
sources += ../csidh/mont.c
sources += ../csidh/csidh.c

includes = $(wildcard ../csidh/*.h ../csidh/p512/*.h csidh.h)

all: $(sources) $(includes) 
	gcc \
	-Wall -Wextra -fsanitize=address \
	-I ../csidh/ \
	-I ../csidh/p512 \
	-I ../CSI-FiSh/implementation/XKCP/bin/generic64/ \
	$(sources) \
	-o test_csike \
	-L ../CSI-FiSh/implementation/XKCP/bin/generic64/ -lkeccak
	
clean:
	rm -f test_csike