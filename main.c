#include <stdio.h>
#include <stdint.h>

uint32_t rol(uint32_t n, uint8_t x) {
    return (n << x) | (n >> (32- x));
}

typedef struct CryptState {
    uint32_t cc_state[16];
    uint32_t rounds;
} CryptState;

void MakeCryptState(CryptState* state, char* key) {

}

// Implemented as specified in RFC 7539 Section-2.1
void QuarterRound(CryptState* state, uint8_t p1, uint8_t p2, uint8_t p3, uint8_t p4) {
     /* a += b; d ^= a; d <<<= 16; Step 1
      * c += d; b ^= c; b <<<= 12; Step 2
      * a += b; d ^= a; d <<<= 8;  Step 3
      * c += d; b ^= c; b <<<= 7;  Step 4
      */
    // Step 1
    uint32_t a = state->cc_state[p1];
    uint32_t b = state->cc_state[p2];
    uint32_t c = state->cc_state[p3];
    uint32_t d = state->cc_state[p4];

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

    state->cc_state[p1] = a;
    state->cc_state[p2] = b;
    state->cc_state[p3] = c;
    state->cc_state[p4] = d;
}

 
int main() {
    CryptState state = {
        .cc_state = { 0x879531e0, 0xc5ecf37d, 0x516461b1,  0xc9a62f8a,
            0x44c20ef3,  0x3390af7f, 0xd9fc690b,  0x2a5f714c,
            0x53372767,  0xb00a5631, 0x974c541a,  0x359e9963,
            0x5c971061,  0x3d631689, 0x2098d9d6,  0x91dbd320},
       .rounds = 0
    };

    QuarterRound(&state, 2, 7, 8, 13);

    int flag = 0;
    if (state.cc_state[2] == 0xbdb886dc && state.cc_state[7] == 0xcfacafd2 && 
            state.cc_state[8] == 0xe46bea80 && state.cc_state[13] == 0xccc07c79)
        flag = 1;

    printf("Test passed = %d\n", flag);
    return 0;
}
