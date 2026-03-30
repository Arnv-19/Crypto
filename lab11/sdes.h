#ifndef SDES_H
#define SDES_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// SDES Constants
#define P10_SIZE 10
#define P8_SIZE 8
#define IP_SIZE 8
#define EP_SIZE 8
#define P4_SIZE 4
#define SBOX_ROWS 4
#define SBOX_COLS 4

// Function Prototypes

// Key Generation
void generate_keys(uint16_t key, uint8_t *k1, uint8_t *k2);

// Core SDES
uint8_t encrypt_byte(uint8_t data, uint8_t k1, uint8_t k2);
uint8_t decrypt_byte(uint8_t data, uint8_t k1, uint8_t k2);

// Modes of Operation
void encrypt_ecb(uint8_t *data, int len, uint16_t key, uint8_t *out);
void decrypt_ecb(uint8_t *data, int len, uint16_t key, uint8_t *out);

void encrypt_cbc(uint8_t *data, int len, uint16_t key, uint8_t iv, uint8_t *out);
void decrypt_cbc(uint8_t *data, int len, uint16_t key, uint8_t iv, uint8_t *out);

void encrypt_cfb(uint8_t *data, int len, uint16_t key, uint8_t iv, uint8_t *out);
void decrypt_cfb(uint8_t *data, int len, uint16_t key, uint8_t iv, uint8_t *out);

void encrypt_ofb(uint8_t *data, int len, uint16_t key, uint8_t iv, uint8_t *out);
void decrypt_ofb(uint8_t *data, int len, uint16_t key, uint8_t iv, uint8_t *out);

void encrypt_ctr(uint8_t *data, int len, uint16_t key, uint8_t ctr, uint8_t *out);
void decrypt_ctr(uint8_t *data, int len, uint16_t key, uint8_t ctr, uint8_t *out);

// Utility
void print_bin(uint8_t n, int bits);

#endif // SDES_H
