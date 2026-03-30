#include "sdes.h"

// Permutation Tables
const int P10[] = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
const int P8[] = {6, 3, 7, 4, 8, 5, 10, 9};
const int IP[] = {2, 6, 3, 1, 4, 8, 5, 7};
const int IP_INV[] = {4, 1, 3, 5, 7, 2, 8, 6};
const int EP[] = {4, 1, 2, 3, 2, 3, 4, 1};
const int P4[] = {2, 4, 3, 1};

const int S0[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 3, 2}
};

const int S1[4][4] = {
    {0, 1, 2, 3},
    {2, 0, 1, 3},
    {3, 0, 1, 0},
    {2, 1, 0, 3}
};

// Utility to perform permutation
// val: input value
// p: permutation array (1-based indices)
// n: size of permutation
// src_bits: number of bits in input val
int permute(int val, const int *p, int n, int src_bits) {
    int result = 0;
    for (int i = 0; i < n; i++) {
        int pos = p[i] - 1; // 0-based index
        // Extract bit at 'pos' from 'val'
        // 'val' bits are indexed from left (MSB) to right (LSB)
        // Bit at pos 0 is (val >> (src_bits - 1 - 0)) & 1
        int bit = (val >> (src_bits - 1 - pos)) & 1;
        result = (result << 1) | bit;
    }
    return result;
}

// Circular Left Shift
int left_shift(int val, int n, int bits) {
    int mask = (1 << bits) - 1;
    val &= mask;
    return ((val << n) | (val >> (bits - n))) & mask;
}

// Key Generation
void generate_keys(uint16_t key, uint8_t *k1, uint8_t *k2) {
    // 1. P10
    int p10 = permute(key, P10, 10, 10);

    // 2. Split and LS-1
    int left = (p10 >> 5) & 0x1F;
    int right = p10 & 0x1F;

    left = left_shift(left, 1, 5);
    right = left_shift(right, 1, 5);

    // 3. P8 for K1
    int combin = (left << 5) | right;
    *k1 = permute(combin, P8, 8, 10);

    // 4. LS-2
    left = left_shift(left, 2, 5);
    right = left_shift(right, 2, 5);

    // 5. P8 for K2
    combin = (left << 5) | right;
    *k2 = permute(combin, P8, 8, 10);
}

// S-Box lookup
int sbox(int input, const int s[4][4]) {
    int row = ((input >> 3) & 2) | (input & 1);
    int col = (input >> 1) & 3;
    return s[row][col];
}

// F-Function
int f_func(int right, int subkey) {
    // 1. EP
    int expanded = permute(right, EP, 8, 4);
    
    // 2. XOR with subkey
    int xor_val = expanded ^ subkey;
    
    // 3. S-Boxes
    int left_nibble = (xor_val >> 4) & 0xF;
    int right_nibble = xor_val & 0xF;
    
    int s0_val = sbox(left_nibble, S0);
    int s1_val = sbox(right_nibble, S1);
    
    // 4. P4
    int combin = (s0_val << 2) | s1_val;
    return permute(combin, P4, 4, 4);
}

// Helper to encrypt/decrypt a single byte
uint8_t process_byte(uint8_t data, uint8_t k1, uint8_t k2) {
    // 1. IP
    int ip_val = permute(data, IP, 8, 8);
    
    int left = (ip_val >> 4) & 0xF;
    int right = ip_val & 0xF;
    
    // 2. Round 1
    int f1 = f_func(right, k1);
    int left_new = left ^ f1;
    
    // Swap
    int temp = left_new;
    left_new = right;
    right = temp; // right_new
    
    // 3. Round 2
    int f2 = f_func(right, k2);
    left_new = left_new ^ f2;
    // No swap after second round
    
    int combin = (left_new << 4) | right;
    
    // 4. IP Inverse
    return permute(combin, IP_INV, 8, 8);
}

uint8_t encrypt_byte(uint8_t data, uint8_t k1, uint8_t k2) {
    return process_byte(data, k1, k2);
}

uint8_t decrypt_byte(uint8_t data, uint8_t k1, uint8_t k2) {
    return process_byte(data, k2, k1); // Reverse keys for decryption
}

// Modes of Operation implementations

void encrypt_ecb(uint8_t *data, int len, uint16_t key, uint8_t *out) {
    uint8_t k1, k2;
    generate_keys(key, &k1, &k2);
    for (int i = 0; i < len; i++) {
        out[i] = encrypt_byte(data[i], k1, k2);
    }
}

void decrypt_ecb(uint8_t *data, int len, uint16_t key, uint8_t *out) {
    uint8_t k1, k2;
    generate_keys(key, &k1, &k2);
    for (int i = 0; i < len; i++) {
        out[i] = decrypt_byte(data[i], k1, k2);
    }
}

void encrypt_cbc(uint8_t *data, int len, uint16_t key, uint8_t iv, uint8_t *out) {
    uint8_t k1, k2;
    generate_keys(key, &k1, &k2);
    uint8_t prev = iv;
    for (int i = 0; i < len; i++) {
        out[i] = encrypt_byte(data[i] ^ prev, k1, k2);
        prev = out[i];
    }
}

void decrypt_cbc(uint8_t *data, int len, uint16_t key, uint8_t iv, uint8_t *out) {
    uint8_t k1, k2;
    generate_keys(key, &k1, &k2);
    uint8_t prev = iv;
    for (int i = 0; i < len; i++) {
        out[i] = decrypt_byte(data[i], k1, k2) ^ prev;
        prev = data[i];
    }
}

void encrypt_cfb(uint8_t *data, int len, uint16_t key, uint8_t iv, uint8_t *out) {
    uint8_t k1, k2;
    generate_keys(key, &k1, &k2);
    uint8_t input_block = iv;
    for (int i = 0; i < len; i++) {
        uint8_t encrypted_iv = encrypt_byte(input_block, k1, k2);
        out[i] = data[i] ^ encrypted_iv;
        input_block = out[i]; // Feedback cipher
    }
}

void decrypt_cfb(uint8_t *data, int len, uint16_t key, uint8_t iv, uint8_t *out) {
    uint8_t k1, k2;
    generate_keys(key, &k1, &k2);
    uint8_t input_block = iv;
    for (int i = 0; i < len; i++) {
        uint8_t encrypted_iv = encrypt_byte(input_block, k1, k2);
        out[i] = data[i] ^ encrypted_iv;
        input_block = data[i]; // Feedback cipher
    }
}

void encrypt_ofb(uint8_t *data, int len, uint16_t key, uint8_t iv, uint8_t *out) {
    uint8_t k1, k2;
    generate_keys(key, &k1, &k2);
    uint8_t input_block = iv;
    for (int i = 0; i < len; i++) {
        uint8_t output_block = encrypt_byte(input_block, k1, k2);
        out[i] = data[i] ^ output_block;
        input_block = output_block; // Feedback output
    }
}

void decrypt_ofb(uint8_t *data, int len, uint16_t key, uint8_t iv, uint8_t *out) {
    // OFB decryption is same as encryption
    encrypt_ofb(data, len, key, iv, out);
}

void encrypt_ctr(uint8_t *data, int len, uint16_t key, uint8_t ctr, uint8_t *out) {
    uint8_t k1, k2;
    generate_keys(key, &k1, &k2);
    for (int i = 0; i < len; i++) {
        uint8_t encrypted_ctr = encrypt_byte(ctr, k1, k2);
        out[i] = data[i] ^ encrypted_ctr;
        ctr++; // Increment counter
    }
}

void decrypt_ctr(uint8_t *data, int len, uint16_t key, uint8_t ctr, uint8_t *out) {
    // CTR decryption is same as encryption
    encrypt_ctr(data, len, key, ctr, out);
}

void print_bin(uint8_t n, int bits) {
    for (int i = bits - 1; i >= 0; i--) {
        printf("%d", (n >> i) & 1);
    }
}
