cmake_minimum_required(VERSION 3.4.1)
project(csidh LANGUAGES C DESCRIPTION "adapted CSIDH with PRF")
enable_language(C ASM)

set(BITS 512) # sets p512 or p1024
set(CSIDH_FILES 
        p${BITS}/constants.c 
        rng.c 
        p${BITS}/limbs.s 
        p${BITS}/fp.s 
        mont.c 
        fp2.c
        csidh.c 
        p${BITS}/inv/fpadd511.s             
        p${BITS}/inv/fpmul2x2_511.c       
        p${BITS}/inv/jump64divsteps2_s511.s  
        p${BITS}/inv/muls64xs64.s
        p${BITS}/inv/fpcneg511.s       
        p${BITS}/inv/fpmul2x2_511_half.c 
        p${BITS}/inv/muls128xs128.s         
        p${BITS}/inv/norm500_511.s
        p${BITS}/inv/fpinv511.c
        p${BITS}/inv/fpmul511.s 
        p${BITS}/inv/muls256xs256.s       
        )

add_library(csidh SHARED ${CSIDH_FILES})
target_include_directories(csidh PUBLIC  "${CMAKE_CURRENT_SOURCE_DIR}" p${BITS})

set_property(SOURCE ${CSIDH_FILES} APPEND_STRING PROPERTY COMPILE_FLAGS " -std=c99 -pedantic -march=native -fPIC -shared -O3 -DNDEBUG -g -Wall -Wextra -fvisibility=hidden -lgmp")

#)
