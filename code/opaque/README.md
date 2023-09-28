# Deviations from Protocols/Existing Projects

Deviations from OPAQUE/X3DH protocol:
- Ext_s and FK do not use HMAC256 but instead KMAC256 to allow for variable length output
- The used KMAC256 function does also not use a domain seperator as described in the X3DH paper, but instead uses a different customization string
- For the password used for encrypting the payload stored on the server, we truncate the output of the SHA512 output and only take the first 256 bits
- Identifier for sid used as input to $F_K$ functions uses username and hostname instead of hash of long-term public keys as described in X3DH paper (username and hostname described in Draft for OPAQUE) 

TLS-OPAQUE:
- Server requires a certificate (probably to sign key share) in order to accept almost all ciphers (only PSK should work without certificate)

SEAL:
- src/seal/util/locks.h to add #include <mutex>
- CMakeLists.txt to compile library as SHARED and not STATIC

emp-tool:
- NetIO: add constructor for already opened socket
- NetIO: remove closing of socket from destructor
- CMakeLists.txt to compile library as SHARED

PQ-MPC:
- CMakeLists.txt adapt c++ standard from c++14 to c++17
- CMakeLists.txt to compile library as SHARED
