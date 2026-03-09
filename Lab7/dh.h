#ifndef DH_H
#define DH_H

#include <stdint.h>

// A utility function to compute (base^exp) % mod
// Used for calculating public keys and the shared secret
long long int power(long long int base, long long int exp, long long int mod) {
    long long int res = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            res = (res * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return res;
}

// Simple XOR encryption/decryption using the shared secret key
void encrypt_decrypt(char *data, int len, long long int key) {
    // We use a simple 8-bit reduction of the key for XOR
    uint8_t byte_key = (uint8_t)(key & 0xFF); 
    for (int i = 0; i < len; i++) {
        data[i] = data[i] ^ byte_key;
    }
}

#endif
