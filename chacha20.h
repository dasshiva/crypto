#ifndef __CHACHA20_H__
#define __CHACHA20_H__

#include <stdint.h>

// Copyright(C) 2025 Shivashish Das. Licensed under the MIT License

void Encrypt(void* data, const uint64_t size, const void* key, 
        const void* nonce);

#define Decrypt(d, s, k, n) Encrypt(d, s, k, n);
// Uncomment if your system does not provide memcpy
// #define MEMCPY_IMPL_NEEDED 
#endif
