#pragma once

#include <opus-psi/Defines.h>

namespace OpusPsi {
    class Log {
    public:
        static void e(const char* tag, const char *format, ...);

        static void v(const char* tag, const char *format, ...);
        static void v(const char* tag, const block& b);
    };
}
