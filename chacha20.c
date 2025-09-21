#include "chacha20.h"

#ifndef MEMCPY_IMPL_NEEDED
#include <string.h>
#endif

#ifdef MEMCPY_IMPL_NEEDED
void* memcpy(void* dest, const void* src, uint64_t size) {
    uint8_t* d = dest;
    uint8_t* s = src;
    while (size > 0) {
        d[size - 1] = s[size - 1];
        size--;
    }

    return dest;
}

#endif

/* This file implements the ChaCha20 Stream Cipher by D.J Bernstein as 
 * specified in RFC 7539. Comments in the code are excerpts from the RFC
 * to explain why something is being done or implementation notes.
 *
 * This implementation of ChaCha20 can be safely used in multi-threaded 
 * programs and assumes a 64 bit environment.
 *
 * It only needs the memcpy() function (optional) from the platform and 
 * an implemenatation of memcpy is also provided if the platform does not
 * provide it.
 */

typedef struct CryptState {
    uint32_t cc_state[16];
    uint8_t  key[32];
    uint8_t  nonce[12];
    uint32_t counter;
} CryptState;

static uint32_t rol(uint32_t n, uint8_t x) {
    return (n << x) | (n >> (32- x));
}

static void AddBlockCount(CryptState* state, const uint32_t count) {
    state->cc_state[12] = count;
}

static void QuarterRound(uint32_t* state, uint8_t p1, uint8_t p2, uint8_t p3, uint8_t p4) {
    /*
     * The basic operation of the ChaCha algorithm is the quarter round.  It
     * operates on four 32-bit unsigned integers, denoted a, b, c, and d.
     * The operation is as follows (in C-like notation):
     * 1.  a += b; d ^= a; d <<<= 16; Step 1
     * 2.  c += d; b ^= c; b <<<= 12; Step 2
     * 3.  a += b; d ^= a; d <<<= 8;  Step 3
     * 4.  c += d; b ^= c; b <<<= 7;  Step 4
     * Where "+" denotes integer addition modulo 2^32, "^" denotes a bitwise
     * Exclusive OR (XOR), and "<<< n" denotes an n-bit left rotation
     * (towards the high bits).*/

    // Step 1
    uint32_t a = state[p1];
    uint32_t b = state[p2];
    uint32_t c = state[p3];
    uint32_t d = state[p4];

    a += b;
    d ^= a;
    d = rol(d, 16);

    // Step 2
    c += d;
    b ^= c;
    b = rol(b, 12);

    // Step 3
    a += b;
    d ^= a;
    d = rol(d, 8);

    // Step 4
    c += d;
    b ^= c;
    b = rol(b, 7);

    state[p1] = a;
    state[p2] = b;
    state[p3] = c;
    state[p4] = d;
}

static void ChaCha20Block(CryptState* state) {
    
    /* The ChaCha20 state is initialized as follows:
     *
     * The first four words (0-3) are constants: 0x61707865, 0x3320646e, 
     * 0x79622d32, 0x6b206574 */
    state->cc_state[0] = 0x61707865;
    state->cc_state[1] = 0x3320646e;
    state->cc_state[2] = 0x79622d32;
    state->cc_state[3] = 0x6b206574;

    /* The next eight words (4-11) are taken from the 256-bit key by
     * reading the bytes in little-endian order, in 4-byte chunks. */
    memcpy(&state->cc_state[4], state->key, 8 * sizeof(uint32_t));

    /* Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
       word is enough for 256 gigabytes of data */
    state->cc_state[12] = state->counter;

    /* Words 13-15 are a nonce, which should not be repeated for the same
     * key.  The 13th word is the first 32 bits of the input nonce taken
     * as a little-endian integer, while the 15th word is the last 32 bits. */
    memcpy(&state->cc_state[13], state->nonce, 3 * sizeof(uint32_t));


    /* The below code implements the chacha20_block pseudocode
     * obtained from the RFC */

    /* inner_block (state):
     *   Qround(state, 0, 4, 8,12)
     *   Qround(state, 1, 5, 9,13)
     *   Qround(state, 2, 6,10,14)
     *   Qround(state, 3, 7,11,15)
     *   Qround(state, 0, 5,10,15)
     *   Qround(state, 1, 6,11,12)
     *   Qround(state, 2, 7, 8,13)
     *   Qround(state, 3, 4, 9,14)
     *   end
     *
     *   chacha20_block(key, counter, nonce):
     *     state = constants | key | counter | nonce
     *     working_state = state
     *     for i=1 upto 10
     *       inner_block(working_state)
     *       end
     *     state += working_state
     *     return serialize(state)
     *     end
    */
    
    uint32_t working_state[16];
    memcpy(working_state, state->cc_state, 16 * sizeof(uint32_t));

    for (int i = 0; i < 10; i++) {
        QuarterRound(working_state, 0, 4, 8, 12);
        QuarterRound(working_state, 1, 5, 9, 13);
        QuarterRound(working_state, 2, 6, 10, 14);
        QuarterRound(working_state, 3, 7, 11, 15);
        QuarterRound(working_state, 0, 5, 10, 15);
        QuarterRound(working_state, 1, 6, 11, 12);
        QuarterRound(working_state, 2, 7, 8, 13);
        QuarterRound(working_state, 3, 4, 9, 14);
    }

    for (int i = 0; i < 16; i++) {
        state->cc_state[i] += working_state[i];
    }

    state->counter++;
}

void Encrypt(void* d, const uint64_t size, const void* k, const void* n) {
    uint8_t* data = d;
    const uint8_t* key = k;
    const uint8_t* nonce = n;

    int64_t i = 0;
    CryptState state;
    memcpy(state.key, k, 8 * sizeof(uint32_t));
    memcpy(state.nonce, n, 3 * sizeof(uint32_t));
    state.counter = 1;

    /* The below code is an implementation of the chacha20_encrypt pseudocode
     * taken from the RFC. */

    /* chacha20_encrypt(key, counter, nonce, plaintext):
     * for j = 0 upto floor(len(plaintext)/64)-1
     *   key_stream = chacha20_block(key, counter+j, nonce)
     *   block = plaintext[(j*64)..(j*64+63)]
     *   encrypted_message +=  block ^ key_stream
     *   end
     * if ((len(plaintext) % 64) != 0)
     *   j = floor(len(plaintext)/64)
     *   key_stream = chacha20_block(key, counter+j, nonce)
     *   block = plaintext[(j*64)..len(plaintext)-1]
     *   encrypted_message += (block^key_stream)[0..len(plaintext)%64]
     *   end
     * return encrypted_message
     * end
    */
    for (i = 0; i < (size/64); i++) {
        ChaCha20Block(&state);
        uint8_t* block = (uint8_t*)state.cc_state;
        for (int j = 0; j < 64; j++) {
            data[i * 64 + j] ^= block[j];
        }
    }

    if (size % 64 != 0) {
        ChaCha20Block(&state);
        uint8_t* block = (uint8_t*)state.cc_state;
        for (int j = 0; j < (size % 64); j++) {
            data[i * 64 + j] ^= block[j];
        }
    }
}



