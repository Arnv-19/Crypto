#ifndef ECC_H
#define ECC_H

#include <stdio.h>
#include <stdlib.h>

// Elliptic curve y^2 = x^3 + a*x + b over F_p
#define P 251
#define A 1
#define B 1

typedef struct {
    int x;
    int y;
    int is_infinity; // 1 if point is at infinity, 0 otherwise
} Point;

// Base point G = (0, 1)
Point G = {0, 1, 0};

// Function prototypes
int modAdd(int a, int b, int m);
int modSub(int a, int b, int m);
int modMul(int a, int b, int m);
int modDiv(int a, int b, int m);
int modInverse(int a, int m);

Point pointAdd(Point P1, Point P2);
Point pointNeg(Point P1);
Point scalarMult(int k, Point P1);
void printPoint(Point p, const char* name);

typedef struct {
    Point C1;
    Point C2;
} Ciphertext;

// Math functions
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

// Point operations
Point pointAdd(Point P1, Point P2) {
    Point R;
    if (P1.is_infinity) return P2;
    if (P2.is_infinity) return P1;

    int lambda;
    if (P1.x == P2.x && P1.y == P2.y) {
        // Point doubling
        if (P1.y == 0) {
            R.is_infinity = 1;
            return R;
        }
        int num = modAdd(modMul(3, modMul(P1.x, P1.x, P), P), A, P);
        int den = modMul(2, P1.y, P);
        lambda = modDiv(num, den, P);
    } else {
        if (P1.x == P2.x) {
            R.is_infinity = 1;
            return R;
        }
        // Point addition
        int num = modSub(P2.y, P1.y, P);
        int den = modSub(P2.x, P1.x, P);
        lambda = modDiv(num, den, P);
    }
    
    if (lambda == -1) {
        R.is_infinity = 1;
        R.x = 0; R.y = 0;
        return R;
    }

    R.x = modSub(modSub(modMul(lambda, lambda, P), P1.x, P), P2.x, P);
    R.y = modSub(modMul(lambda, modSub(P1.x, R.x, P), P), P1.y, P);
    R.is_infinity = 0;
    
    return R;
}

Point pointNeg(Point P1) {
    if (P1.is_infinity) return P1;
    Point R;
    R.x = P1.x;
    R.y = modSub(0, P1.y, P);
    R.is_infinity = 0;
    return R;
}

Point scalarMult(int k, Point P1) {
    Point R = {0, 0, 1}; // Infinity
    Point Q = P1;
    
    if (k < 0) {
        Q = pointNeg(P1);
        k = -k;
    }

    while (k > 0) {
        if (k % 2 == 1) {
            R = pointAdd(R, Q);
        }
        Q = pointAdd(Q, Q);
        k /= 2;
    }
    return R;
}

void printPoint(Point p, const char* name) {
    if (p.is_infinity) printf("%s = Infinity\n", name);
    else printf("%s = (%d, %d)\n", name, p.x, p.y);
}

#endif // ECC_H
