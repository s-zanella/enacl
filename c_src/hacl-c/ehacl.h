/* MIT License
 *
 * Copyright (c) 2016-2017 INRIA and Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/**************************************************************************
 * WARNING:
 * This file is handwritten and MUST be reviewed properly before use
 **************************************************************************/

#include <inttypes.h>
#include <sodium.h>

int hacl_scalarmult_curve25519(uint8_t *out, const uint8_t *secret, const uint8_t *point);

int hacl_sign_ed25519_keypair(uint8_t pk[32], uint8_t sk[64]);

int hacl_sign_ed25519_sk_to_curve25519(uint8_t *public_key, uint8_t *secret_key);

int hacl_sign_keypair(uint8_t pk[32], uint8_t sk[64]);

int hacl_sign(uint8_t *signed_msg, uint64_t *signed_len, const uint8_t *msg, uint64_t msg_len, const uint8_t *sk);

int hacl_sign_open(uint8_t *unsigned_msg, uint64_t *unsigned_msg_len, const uint8_t *msg, uint64_t msg_len, const uint8_t *pk);

int hacl_secretbox(uint8_t *cipher, const uint8_t *msg, uint64_t msg_len, const uint8_t *nonce, const uint8_t *key);

int hacl_secretbox_open(uint8_t *msg, const uint8_t *cipher, uint64_t cipher_len, const uint8_t *nonce, const uint8_t *key);

int hacl_stream_chacha20(uint8_t *cipher, uint64_t cipher_len, const uint8_t *nonce, const uint8_t *key);

int hacl_stream_chacha20_xor(uint8_t *cipher, const uint8_t *msg, uint64_t cipher_len, const uint8_t *nonce, const uint8_t *key);

int hacl_stream(uint8_t *cipher, uint64_t cipher_len, const uint8_t *nonce, const uint8_t *key);

int hacl_stream_xor(uint8_t *cipher, const uint8_t *msg, uint64_t cipher_len, const uint8_t *nonce, const uint8_t *key);

int hacl_auth(uint8_t *output, const uint8_t *input, uint64_t input_len, const uint8_t *key);

int hacl_auth_verify(const uint8_t *tag, const uint8_t *input, uint64_t input_len, const uint8_t *key);

int hacl_onetimeauth(uint8_t *output, const uint8_t *input, uint64_t input_len, const uint8_t *key);

int hacl_onetimeauth_verify(const uint8_t *auth, const uint8_t *input, uint64_t input_len, const uint8_t *key);

int hacl_aead_chacha20poly1305_encrypt(uint8_t *c, uint64_t *clen, uint8_t *m, uint64_t mlen, uint8_t *ad, uint64_t ad_len, uint8_t *nsec, uint8_t *npub, uint8_t *k);

int hacl_aead_chacha20poly1305_decrypt(uint8_t *m, uint64_t *mlen, uint8_t *nsec, uint8_t *c, uint64_t clen, uint8_t *ad, uint64_t ad_len, uint8_t *npub, uint8_t *k);
