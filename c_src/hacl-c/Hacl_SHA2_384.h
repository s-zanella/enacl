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


#include "kremlib.h"
#ifndef __Hacl_SHA2_384_H
#define __Hacl_SHA2_384_H




extern uint32_t Hacl_SHA2_384_size_word;

extern uint32_t Hacl_SHA2_384_size_hash_w;

extern uint32_t Hacl_SHA2_384_size_block_w;

extern uint32_t Hacl_SHA2_384_size_hash;

extern uint32_t Hacl_SHA2_384_size_block;

extern uint32_t Hacl_SHA2_384_size_hash_final_w;

extern uint32_t Hacl_SHA2_384_size_hash_final;

extern uint32_t Hacl_SHA2_384_size_k_w;

extern uint32_t Hacl_SHA2_384_size_ws_w;

extern uint32_t Hacl_SHA2_384_size_whash_w;

extern uint32_t Hacl_SHA2_384_size_count_w;

extern uint32_t Hacl_SHA2_384_size_len_8;

extern uint32_t Hacl_SHA2_384_size_state;

extern uint32_t Hacl_SHA2_384_pos_k_w;

extern uint32_t Hacl_SHA2_384_pos_ws_w;

extern uint32_t Hacl_SHA2_384_pos_whash_w;

extern uint32_t Hacl_SHA2_384_pos_count_w;

void Hacl_SHA2_384_init(uint64_t *state);

void Hacl_SHA2_384_update(uint64_t *state, uint8_t *data_8);

void Hacl_SHA2_384_update_multi(uint64_t *state, uint8_t *data, uint32_t n1);

void Hacl_SHA2_384_update_last(uint64_t *state, uint8_t *data, uint32_t len);

void Hacl_SHA2_384_finish(uint64_t *state, uint8_t *hash1);

void Hacl_SHA2_384_hash(uint8_t *hash1, uint8_t *input, uint32_t len);

#define __Hacl_SHA2_384_H_DEFINED
#endif
