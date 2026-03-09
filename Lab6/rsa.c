#include "rsa.h"

// Euclidean Algorithm for GCD
llong gcd(llong a, llong b) {
    while (b != 0) {
        llong temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Modular Exponentiation: (base^exp) % mod
llong modExp(llong base, llong exp, llong mod) {
    llong result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) // If exp is odd, multiply base with result
            result = (result * base) % mod;
        exp = exp >> 1; // exp = exp / 2
        base = (base * base) % mod;
    }
    return result;
}

// Basic Primality Test
int isPrime(llong n) {
    if (n <= 1) return 0;
    if (n <= 3) return 1;
    if (n % 2 == 0 || n % 3 == 0) return 0;
    for (llong i = 5; i * i <= n; i = i + 6)
        if (n % i == 0 || n % (i + 2) == 0)
            return 0;
    return 1;
}

// Generate RSA Keys
RSA_Keys generateKeys() {
    RSA_Keys keys;
    llong p, q, n, phi, e, d;
    
    srand(time(0));
    
    // Select two random primes from a small range for demonstration
    // Range [50, 200] is safe for 'int' arithmetic but 'long long' is used.
    // We want n to be large enough to hold char values (0-255) if we encrypt chars, 
    // but here we encrypt integers.
    
    do { p = (rand() % 100) + 11; } while (!isPrime(p));
    do { q = (rand() % 100) + 11; } while (!isPrime(q) || p == q);
    
    n = p * q;
    phi = (p - 1) * (q - 1);
    
    // Choose e such that 1 < e < phi and gcd(e, phi) = 1
    for (e = 3; e < phi; e += 2) {
        if (gcd(e, phi) == 1) break;
    }
    
    // Calculate d such that (d * e) % phi = 1
    // Using Extended Euclidean Logic strictly for modular inverse
    // Or simple brute force for small numbers
    for (d = 1; d < phi; d++) {
        if ((d * e) % phi == 1) break;
    }
    
    keys.e = e;
    keys.n = n;
    keys.d = d;
    
    printf("\n--- Key Generation Steps ---\n");
    printf("1. Selected Primes: p = %lld, q = %lld\n", p, q);
    printf("2. Computed n = p * q = %lld\n", n);
    printf("3. Computed Phi(n) = (p-1)*(q-1) = %lld\n", phi);
    printf("4. Selected Public Exponent e = %lld (gcd(%lld, %lld) = 1)\n", e, e, phi);
    printf("5. Computed Private Exponent d = %lld ( (%lld * %lld) %% %lld = 1 )\n", d, d, e, phi);
    printf("----------------------------\n");
    printf("Public Key:  {%lld, %lld}\n", e, n);
    printf("Private Key: {%lld, %lld}\n", d, n);
    printf("----------------------------\n\n");
    
    return keys;
}

// Encryption: C = M^e mod n
llong encrypt(llong msg, llong e, llong n) {
    if (msg >= n) {
        printf("Error: Message %lld is >= Modulus %lld. Encryption will be ambiguous.\n", msg, n);
    }
    llong cipher = modExp(msg, e, n);
    printf("Encryption Step: %lld^%lld mod %lld = %lld\n", msg, e, n, cipher);
    return cipher;
}

// Decryption: M = C^d mod n
llong decrypt(llong cipher, llong d, llong n) {
    llong msg = modExp(cipher, d, n);
    printf("Decryption Step: %lld^%lld mod %lld = %lld\n", cipher, d, n, msg);
    return msg;
}
