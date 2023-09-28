#pragma once

#include <cstdint>
#include <array>
#include <span>
#include <opus-psi/Defines.h>

#if defined(HAVE_NEON)
#include <arm_acle.h>
#include <arm_neon.h>
#else
#include <wmmintrin.h>
#include <xmmintrin.h>
#endif

namespace OpusPsi {
class AES {
  template <int x>
  friend class MultiKeyAES;

 public:
  AES();
  AES(const block &key);
  AES(const uint8_t *key);

  void setKey(const block &key);
  void setKey(const uint8_t *key);

  void encryptECB(const block &plaintext, block &ciphertext) const;
  block encryptECB(const block &plaintext) const {
    block tmp;
    encryptECB(plaintext, tmp);
    return tmp;
  }

  void decryptECB(const block &ciphertext, block &plaintext) const;
  block decryptECB(const block &ciphertext) const {
    block tmp;
    decryptECB(ciphertext, tmp);
    return tmp;
  }
  void encryptECBBlocks(const block *plaintexts, uint64_t blockLength,
                        block *ciphertexts) const;

  void encryptCTR(uint64_t baseIdx, uint64_t blockLength,
                  block *ciphertext) const;
  block key;

 private:
  block mRoundKeysEnc[11];
  block mRoundKeysDec[11];
#if defined(HAVE_NEON)
  void keyschedule(const uint8_t *key);
#endif
};
// An AES instance with a fixed and public key
}  // namespace droidCrypto

//extern "C" JNIEXPORT void JNICALL
//Java_com_example_mobile_1psi_droidCrypto_Crypto_AES_fixedKeyEnc(JNIEnv *, jclass,
//                                                           jobject, jobject);
