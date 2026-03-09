#ifndef SSS_H
#define SSS_H

#include <stdio.h>
#include <stdlib.h>

#define P 251 // Prime field

typedef struct {
    int x;
    int y; // The share value
} Share;

// Math functions over prime field
int modAdd(int a, int b, int m) {
    int res = (a + b) % m;
    if (res < 0) res += m;
    return res;
}

int modSub(int a, int b, int m) {
    int res = (a - b) % m;
    if (res < 0) res += m;
    return res;
}

int modMul(int a, int b, int m) {
    int res = (a * b) % m;
    if (res < 0) res += m;
    return res;
}

int modInverse(int a, int m) {
    a = a % m;
    if (a < 0) a += m;
    for (int x = 1; x < m; x++)
        if ((a * x) % m == 1)
            return x;
    return -1; 
}

int modDiv(int a, int b, int m) {
    int inv = modInverse(b, m);
    if (inv == -1) return -1;
    return modMul(a, inv, m);
}

// Evaluate polynomial at x: f(x) = S + a_1*x + a_2*x^2 + ... (mod P)
// coeffs[0] is the secret S.
int evaluatePolynomial(int* coeffs, int degree, int x) {
    int result = 0;
    int x_pow = 1;
    for (int i = 0; i <= degree; i++) {
        result = modAdd(result, modMul(coeffs[i], x_pow, P), P);
        x_pow = modMul(x_pow, x, P);
    }
    return result;
}

// Lagrange Interpolation to find f(0) given M shares
int lagrangeInterpolate(Share* shares, int M) {
    int secret = 0;
    
    for (int i = 0; i < M; i++) {
        int numerator = 1;
        int denominator = 1;
        
        for (int j = 0; j < M; j++) {
            if (i == j) continue;
            
            // L_i(0) basis polynomial calculation
            numerator = modMul(numerator, modSub(0, shares[j].x, P), P);
            denominator = modMul(denominator, modSub(shares[i].x, shares[j].x, P), P);
        }
        
        int L_i = modDiv(numerator, denominator, P);
        int term = modMul(shares[i].y, L_i, P);
        secret = modAdd(secret, term, P);
    }
    
    return secret;
}

#endif // SSS_H
