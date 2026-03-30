#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <math.h>
#include "common.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080

// Modular exponentiation
long long modPow(long long base, long long exp, long long mod) {
    long long res = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            res = (res * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return res;
}

// Extended Euclidean Algorithm to find modular inverse
long long modInverse(long long a, long long m) {
    long long m0 = m;
    long long y = 0, x = 1;

    if (m == 1) return 0;

    while (a > 1) {
        long long q = a / m;
        long long t = m;

        m = a % m, a = t;
        t = y;

        y = x - q * y;
        x = t;
    }

    if (x < 0) x += m0;

    return x;
}

// GCD
long long gcd(long long a, long long b) {
    if (b == 0) return a;
    return gcd(b, a % b);
}

int main() {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    Payload payload;
    
    long long p, g, x, m, k;

    printf("--- ElGamal Digital Signature (Signer/Client) ---\n");
    printf("Enter Prime Number (p): ");
    scanf("%lld", &p);
    printf("Enter Generator (g) < p: ");
    scanf("%lld", &g);
    printf("Enter Private Key (x) [1 to p-2]: ");
    scanf("%lld", &x);
    printf("Enter Message (m) as an Integer: ");
    scanf("%lld", &m);
    
    printf("Enter a random integer (k) such that gcd(k, p-1) = 1: ");
    scanf("%lld", &k);
    
    if (gcd(k, p-1) != 1) {
        printf("Error: gcd(k, p-1) is not 1. Re-run again.\n");
        return 1;
    }

    long long y = modPow(g, x, p);
    printf("\nCalculated Public Key (y) = %lld\n", y);

    // Compute signature (r, s)
    long long r = modPow(g, k, p);
    long long k_inv = modInverse(k, p-1);
    
    // Make sure temp is properly handled if negative
    long long temp = m - x * r;
    temp = (temp % (p-1) + (p-1)) % (p-1);
    
    long long s = (k_inv * temp) % (p-1);
    
    printf("Generated Signature: r = %lld, s = %lld\n", r, s);

    // Set up payload
    payload.pub_key.p = p;
    payload.pub_key.g = g;
    payload.pub_key.y = y;
    payload.sig.r = r;
    payload.sig.s = s;
    payload.sig.m = m;

    printf("\nInitializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("Failed. Error Code: %d\n", WSAGetLastError());
        return 1;
    }

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket: %d\n", WSAGetLastError());
        return 1;
    }

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Connection error\n");
        return 1;
    }
    
    printf("Connected to server. Sending payload with signature...\n");
    send(sock, (char*)&payload, sizeof(Payload), 0);
    printf("Payload sent successfully.\n");
    
    closesocket(sock);
    WSACleanup();
    return 0;
}
