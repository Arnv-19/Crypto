#ifndef RSA_H
#define RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

// Using long long to prevent overflow for small-ish primes
typedef long long llong;

// Structure to hold keys
typedef struct {
    llong e;
    llong d;
    llong n;
} RSA_Keys;

// Function Prototypes
llong gcd(llong a, llong b);
llong modExp(llong base, llong exp, llong mod);
int isPrime(llong n);
RSA_Keys generateKeys();
llong encrypt(llong msg, llong e, llong n);
llong decrypt(llong cipher, llong d, llong n);

#endif // RSA_H
