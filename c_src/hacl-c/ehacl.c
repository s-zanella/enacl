#include "Hacl_Curve25519.h"
#include "Hacl_Chacha20.h"
#include "Hacl_Salsa20.h"
#include "Hacl_HMAC_SHA2_256.h"
#define Hacl_Impl_Poly1305_64_State_poly1305_state Hacl_Impl_Poly1305_64_State_poly1305_state_poly
#include "Hacl_Poly1305_64.h"
#undef Hacl_Impl_Poly1305_64_State_poly1305_state
#define Hacl_Impl_Poly1305_64_State_poly1305_state Hacl_Impl_Poly1305_64_State_poly1305_state_aead
#include "Hacl_Chacha20Poly1305.h"
#undef Hacl_Impl_Poly1305_64_State_poly1305_state

#define K___uint32_t_uint8_t_ K___uint32_t_uint8_t_ed
#include "Hacl_Ed25519.h"
#undef K___uint32_t_uint8_t_
#define K___uint32_t_uint8_t_ K___uint32_t_uint8_t_sha256
#include "Hacl_SHA2_256.h"
#undef K___uint32_t_uint8_t_
#define K___uint32_t_uint8_t_ K___uint32_t_uint8_t_sha512
#include "Hacl_SHA2_512.h"
#undef K___uint32_t_uint8_t_
#include "NaCl.h"

#include <ehacl.h>

#define EXPORT __attribute__((visibility("default")))

extern void randombytes(uint8_t *bytes, uint64_t bytes_len);

// Exported symbols use the hacl_ prefix rather than crypto_

EXPORT
int hacl_scalarmult_curve25519(uint8_t *out, const uint8_t *secret, const uint8_t *point){
  Hacl_Curve25519_crypto_scalarmult(out, (uint8_t*)secret, (uint8_t*)point);
  return 0;
}

EXPORT
int hacl_sign_ed25519_keypair(uint8_t pk[32], uint8_t sk[64]){
  randombytes(sk, 32 * sizeof(uint8_t));
  Hacl_Ed25519_secret_to_public(pk, sk);
  for (int i = 0; i < 32; i++) sk[32+i] = pk[i];
  return 0;
}

EXPORT
int hacl_sign_ed25519_sk_to_curve25519(uint8_t *public_key, uint8_t *secret_key){
  Hacl_Ed25519_secret_to_public(public_key, secret_key);
  return 0;
}

EXPORT
int hacl_sign_keypair(uint8_t pk[32], uint8_t sk[64]){
  randombytes(sk, 32 * sizeof(uint8_t));
  Hacl_Ed25519_secret_to_public(pk, sk);
  for (int i = 0; i < 32; i++) sk[32+i] = pk[i];
  return 0;
}

EXPORT
int hacl_sign(uint8_t *signed_msg, uint64_t *signed_len, const uint8_t *msg, uint64_t msg_len, const uint8_t *sk){
  Hacl_Ed25519_sign(signed_msg, (uint8_t *)sk, (uint8_t *)msg, msg_len);
  memmove(signed_msg+64, msg, msg_len * sizeof(uint8_t));
  *signed_len = msg_len + 64;
  return 0;
}

EXPORT
int hacl_sign_open(uint8_t *unsigned_msg, uint64_t *unsigned_msg_len, const uint8_t *msg, uint64_t msg_len, const uint8_t *pk){
  uint32_t res;
  res = Hacl_Ed25519_verify((uint8_t *)pk, (uint8_t *)msg+64, msg_len - 64, (uint8_t *)msg);
  if (res){
    memmove(unsigned_msg, msg+64, sizeof(uint8_t) * (msg_len-64));
    *unsigned_msg_len = msg_len - 64;
    return 0;
  } else {
    return -1;
  }
}

int hacl_secretbox_easy(uint8_t *c, uint8_t *m, uint64_t mlen, uint8_t *n, uint8_t *k){
  return NaCl_crypto_secretbox_easy(c, m, mlen, n, k);
}

EXPORT
int hacl_secretbox(uint8_t *cipher, const uint8_t *msg, uint64_t msg_len, const uint8_t *nonce, const uint8_t *key){
  return hacl_secretbox_easy(cipher, (uint8_t *)msg, msg_len - 32, (uint8_t *)nonce, (uint8_t *)key);
}

int hacl_secretbox_open_detached(uint8_t *m, uint8_t *c, uint8_t *mac, uint64_t clen, uint8_t *n, uint8_t *k){
  return NaCl_crypto_secretbox_open_detached(m, c, mac, clen, n, k);
}

EXPORT
int hacl_secretbox_open(uint8_t *msg, const uint8_t *cipher, uint64_t cipher_len, const uint8_t *nonce, const uint8_t *key){
  return hacl_secretbox_open_detached(msg, (uint8_t *)cipher, (uint8_t *)cipher + 16, cipher_len - 32, (uint8_t *)nonce, (uint8_t *)key);
}

EXPORT
int hacl_stream_chacha20(uint8_t *cipher, uint64_t cipher_len, const uint8_t *nonce, const uint8_t *key){
  uint8_t subkey[32];
  memset(cipher, 0, cipher_len * sizeof(uint8_t));
  Hacl_Salsa20_hsalsa20(subkey, (uint8_t *)key, (uint8_t *)nonce);
  Hacl_Salsa20_salsa20(cipher, cipher, cipher_len, subkey, (uint8_t *)nonce + 16, 0);
  return 0;
}

EXPORT
int hacl_stream_chacha20_xor(uint8_t *cipher, const uint8_t *msg, uint64_t cipher_len, const uint8_t *nonce, const uint8_t *key){
  uint8_t subkey[32];
  memset(cipher, 0, cipher_len * sizeof(uint8_t));
  Hacl_Salsa20_hsalsa20(subkey, (uint8_t *)key, (uint8_t *)nonce);
  Hacl_Salsa20_salsa20(cipher, (uint8_t *)msg, cipher_len, subkey, (uint8_t *)nonce + 16, 0);
  return 0;
}

EXPORT
int hacl_stream(uint8_t *cipher, uint64_t cipher_len, const uint8_t *nonce, const uint8_t *key){
  uint8_t subkey[32];
  memset(cipher, 0, cipher_len * sizeof(uint8_t));
  Hacl_Salsa20_hsalsa20(subkey, (uint8_t *)key, (uint8_t *)nonce);
  Hacl_Salsa20_salsa20(cipher, cipher, cipher_len, subkey, (uint8_t *)nonce + 16, 0);
  return 0;
}

EXPORT
int hacl_stream_xor(uint8_t *cipher, const uint8_t *msg, uint64_t cipher_len, const uint8_t *nonce, const uint8_t *key){
  uint8_t subkey[32];
  memset(cipher, 0, cipher_len * sizeof(uint8_t));
  Hacl_Salsa20_hsalsa20(subkey, (uint8_t *)key, (uint8_t *)nonce);
  Hacl_Salsa20_salsa20(cipher, (uint8_t *)msg, cipher_len, subkey, (uint8_t *)nonce + 16, 0);
  return 0;
}

EXPORT
int hacl_auth(uint8_t *output, const uint8_t *input, uint64_t input_len, const uint8_t *key){
  Hacl_HMAC_SHA2_256_hmac(output, (uint8_t *)key, 32, (uint8_t *)input, input_len);
  return 0;
}

EXPORT
int hacl_auth_verify(const uint8_t *tag, const uint8_t *input, uint64_t input_len, const uint8_t *key){
  uint8_t recomputed_tag[32], tmp = 0xff;
  Hacl_HMAC_SHA2_256_hmac(recomputed_tag, (uint8_t *)key, 32, (uint8_t *)input, input_len);
  for (int i = 0; i < 32; i++){
    tmp = tmp & FStar_UInt8_eq_mask((uint8_t)tag[i], recomputed_tag[i]);
  }
  tmp >>= 7;
  return (int)tmp - 1;
}

EXPORT
int hacl_onetimeauth(uint8_t *output, const uint8_t *input, uint64_t input_len, const uint8_t *key){
  Hacl_Poly1305_64_crypto_onetimeauth(output, (uint8_t *)input, input_len, (uint8_t *)key);
  return 0;
}

EXPORT
int hacl_onetimeauth_verify(const uint8_t *auth, const uint8_t *input, uint64_t input_len, const uint8_t *key){
  uint8_t tag[16], tmp = 0xff;
  Hacl_Poly1305_64_crypto_onetimeauth(tag, (uint8_t *)input, input_len, (uint8_t *)key);
  for (int i = 0; i < 16; i++){
    tmp = tmp & FStar_UInt8_eq_mask(tag[i], (uint8_t)auth[i]);
  }
  tmp >>= 7;
  return (int)tmp - 1;
}

EXPORT
int hacl_aead_chacha20poly1305_encrypt(uint8_t *c, uint64_t *clen, uint8_t *m, uint64_t mlen, uint8_t *ad, uint64_t ad_len, uint8_t *nsec, uint8_t *npub, uint8_t *k){
  Hacl_Chacha20Poly1305_aead_encrypt(c, c + mlen, m, mlen, ad, ad_len, k, npub);
  return 0;
}

EXPORT
int hacl_aead_chacha20poly1305_decrypt(uint8_t *m, uint64_t *mlen, uint8_t *nsec, uint8_t *c, uint64_t clen, uint8_t *ad, uint64_t ad_len, uint8_t *npub, uint8_t *k){
  uint32_t mlen_ = clen - crypto_aead_chacha20poly1305_ABYTES;
  uint32_t res = Hacl_Chacha20Poly1305_aead_decrypt(m, c, mlen_, c + mlen_, ad, ad_len, k, npub);
  if (res == 0) {
    if (mlen != NULL) { *mlen = mlen_; }
    return 0;
  }
  else {
    return -1;
  }
}
