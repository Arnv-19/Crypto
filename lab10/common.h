#ifndef COMMON_H
#define COMMON_H

typedef struct {
    long long p;
    long long g;
    long long y;
} PublicKey;

typedef struct {
    long long r;
    long long s;
    long long m; // message
} Signature;

typedef struct {
    PublicKey pub_key;
    Signature sig;
} Payload;

#endif
