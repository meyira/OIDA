#pragma once

#include <opus-psi/Defines.h>
#include <opus-psi/PRNG.h>

#include <fstream>
#include <iostream>

namespace OpusPsi {
    class SecureRandom {

        public:
            SecureRandom() {
                std::ifstream f("/dev/urandom", std::ifstream::binary);
                block seed;
                f.read((char*)&seed, sizeof(block));
                p.SetSeed(seed);
                f.close();
            }

            uint64_t rand();
            block randBlock();
            std::vector<block> randBlocks(size_t count);

            void randBytes(uint8_t* buffer, size_t len);

        private:
            PRNG p;

    };
}
