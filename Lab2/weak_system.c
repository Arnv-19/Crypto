/*
 * LAB II - Cryptography and Network Security
 * Weak Authentication System (Composite Modulus)
 * 
 * System Parameters:
 *   n = 15 (Composite: 3 × 5)
 *   k = 11 (Secret key)
 * 
 * Demonstrates:
 *   - Authentication using Token = User_ID^k mod n
 *   - GCD-based factorization attack
 *   - Replay attack
 *   - Token prediction attack
 *   - Impersonation attack
 * 
 * Compile: gcc weak_system.c -o weak_system.exe
 * Run: weak_system.exe
 */

#include <stdio.h>
#include <stdlib.h>

// ============== SYSTEM PARAMETERS ==============
#define MODULUS 15          // n = 15 (Composite: 3 × 5)
#define SECRET_KEY 11       // k = 11 (Shared secret)

// ============== FUNCTION PROTOTYPES ==============
long long mod_exp(long long base, long long exp, long long mod);
int gcd(int a, int b);
int euler_totient(int n);
void print_section(const char* title);
void show_system_setup();
void legitimate_authentication();
void attacker_passive_capture();
void attacker_gcd_check();
void system_breaks();
void prime_factorization();
void compute_euler_function();
void demonstrate_token_repetition();
void attack_1_replay();
void attack_2_token_prediction();
void attack_3_impersonation();

// ============== CORE FUNCTIONS ==============

// Modular Exponentiation: base^exp mod mod
long long mod_exp(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

// GCD using Euclidean Algorithm
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Euler Totient Function
int euler_totient(int n) {
    int result = 0;
    for (int i = 1; i < n; i++) {
        if (gcd(i, n) == 1)
            result++;
    }
    return result;
}

// Print section header
void print_section(const char* title) {
    printf("\n");
    printf("========================================\n");
    printf(" %s\n", title);
    printf("========================================\n");
}

// ============== DEMONSTRATION FUNCTIONS ==============

// Show initial system setup
void show_system_setup() {
    print_section("EXPERIMENTAL SETUP");
    printf("System Parameters:\n");
    printf("  n = %d (modulus)\n", MODULUS);
    printf("  k = %d (secret key)\n\n", SECRET_KEY);
    
    printf("Entity Knowledge:\n");
    printf("  Client:   Knows k? YES\n");
    printf("  Server:   Knows k? YES\n");
    printf("  Attacker: Knows k? NO\n\n");
    
    printf("Public & Private Values:\n");
    printf("  User_ID   - Public\n");
    printf("  n         - Public\n");
    printf("  k         - Secret (Shared)\n");
    printf("  Token     - Public (proof sent)\n");
}

// Legitimate authentication
void legitimate_authentication() {
    print_section("LEGITIMATE AUTHENTICATION");
    
    int user_id = 2;
    
    // Client side
    printf("CLIENT SIDE:\n");
    printf("1. User_ID = %d\n", user_id);
    long long token = mod_exp(user_id, SECRET_KEY, MODULUS);
    printf("2. Token = %d^%d mod %d = %lld\n", user_id, SECRET_KEY, MODULUS, token);
    printf("\nClient sends: User_ID=%d ; Token=%lld\n", user_id, token);
    
    // Server side
    printf("\nSERVER SIDE:\n");
    long long server_check = mod_exp(user_id, SECRET_KEY, MODULUS);
    printf("Server recomputes: %d^%d mod %d = %lld\n", 
           user_id, SECRET_KEY, MODULUS, server_check);
    
    // Result
    printf("\nRESULT:\n");
    if (token == server_check) {
        printf("Token = Server recomputes\n");
        printf("Match -> Authentication SUCCESS\n");
    }
}

// Attacker captures traffic
void attacker_passive_capture() {
    print_section("ATTACKER (Passive Attack)");
    
    printf("Attacker captures traffic using Wireshark.\n\n");
    printf("Attacker sees:\n");
    printf("1. User_ID = 2\n");
    printf("2. Token = %lld\n", mod_exp(2, SECRET_KEY, MODULUS));
    printf("3. n = %d\n\n", MODULUS);
    printf("This is a CONFIDENTIALITY attack.\n");
}

// Attacker checks GCD
void attacker_gcd_check() {
    print_section("ATTACKER CHECKS GCD");
    
    int user_id = 2;
    int g = gcd(user_id, MODULUS);
    
    printf("Does this User_ID share any common factor with n?\n");
    printf("Attacker computes: gcd(%d, %d) = %d\n\n", user_id, MODULUS, g);
    
    if (g == 1) {
        printf("%d and %d have nothing in common.\n", user_id, MODULUS);
        printf("No break yet.\n");
    }
}

// System breaks when one user is bad
void system_breaks() {
    print_section("SYSTEM BREAKS WHEN ONE USER IS BAD");
    
    int bad_user_id = 3;
    int g = gcd(bad_user_id, MODULUS);
    
    printf("Another user logs in: User_ID = %d\n", bad_user_id);
    printf("Attacker computes: gcd(%d, %d) = %d\n\n", bad_user_id, MODULUS, g);
    
    if (g > 1) {
        printf("%d is a factor of the system number %d.\n", g, MODULUS);
        printf("\n>>> SYSTEM IS BROKEN HERE <<<\n");
    }
}

// Prime factorization (no guessing)
void prime_factorization() {
    print_section("PRIME FACTORIZATION (NO GUESSING)");
    
    printf("Once attacker knows: gcd(3, %d) = 3\n\n", MODULUS);
    printf("Then:\n");
    printf("  %d ÷ 3 = %d\n", MODULUS, MODULUS/3);
    printf("  %d = 3 × %d\n\n", MODULUS, MODULUS/3);
    printf("Prime factorization achieved\n");
    printf("System structure REVEALED\n");
}

// Compute Euler's function
void compute_euler_function() {
    print_section("EULER'S FUNCTION");
    
    int phi = euler_totient(MODULUS);
    
    printf("φ(%d) = number of values less than %d that are coprime with %d\n", 
           MODULUS, MODULUS, MODULUS);
    
    printf("\nThey are: ");
    int count = 0;
    for (int i = 1; i < MODULUS; i++) {
        if (gcd(i, MODULUS) == 1) {
            printf("%d", i);
            count++;
            if (count < phi) printf(", ");
        }
    }
    printf(" -> %d values\n", phi);
    printf("\nφ(%d) = %d\n", MODULUS, phi);
}

// Demonstrate token repetition
void demonstrate_token_repetition() {
    print_section("TOKENS REPEAT");
    
    int user_id = 2;
    printf("Let: User_ID = %d\n", user_id);
    printf("Compute powers:\n\n");
    
    int phi = euler_totient(MODULUS);
    
    for (int k = 1; k <= phi + 2; k++) {
        long long token = mod_exp(user_id, k, MODULUS);
        printf("%d^%d mod %d = %lld", user_id, k, MODULUS, token);
        
        if (k == phi + 1) {
            printf(" <- repeats\n");
        } else {
            printf("\n");
        }
    }
    
    printf("\nCycle length = %d = φ(%d)\n", phi, MODULUS);
    printf("Even if k is secret, outputs repeat\n");
}

// Attack 1: Replay
void attack_1_replay() {
    print_section("ATTACK-1: REPLAY ATTACK");
    
    printf("Attacker resends: User_ID = 2 and Token = %lld\n", 
           mod_exp(2, SECRET_KEY, MODULUS));
    printf("Server checks: 2^k mod %d = %lld\n", 
           MODULUS, mod_exp(2, SECRET_KEY, MODULUS));
    printf("\nAccepted\n");
    printf(">>> Attacker logged in as User_ID = 2 <<<\n");
}

// Attack 2: Token prediction
void attack_2_token_prediction() {
    print_section("ATTACK-2: TOKEN PREDICTION");
    
    int user_id = 2;
    long long target = mod_exp(user_id, SECRET_KEY, MODULUS);
    
    printf("Even without knowing k, attacker finds matching tokens:\n\n");
    printf("%d^1  mod %d = %lld\n", user_id, MODULUS, mod_exp(user_id, 1, MODULUS));
    printf("%d^%d mod %d = %lld\n", user_id, SECRET_KEY, MODULUS, target);
    printf("%d^%d mod %d = %lld\n", user_id, SECRET_KEY + euler_totient(MODULUS), 
           MODULUS, mod_exp(user_id, SECRET_KEY + euler_totient(MODULUS), MODULUS));
    
    printf("\nMany k values -> same token\n");
    printf(">>> Secret k becomes MEANINGLESS <<<\n");
}

// Attack 3: Impersonation
void attack_3_impersonation() {
    print_section("ATTACK-3: IMPERSONATION");
    
    int fake_user = 4;
    printf("Attacker chooses: User_ID = %d\n", fake_user);
    printf("Compute:\n");
    
    for (int k = 1; k <= 4; k++) {
        printf("  %d^%d mod %d = %lld\n", 
               fake_user, k, MODULUS, mod_exp(fake_user, k, MODULUS));
    }
    
    long long attack_token = mod_exp(fake_user, 3, MODULUS);
    printf("\nAttacker sends: User_ID = %d ; Token = %lld\n", fake_user, attack_token);
    printf("Server checks: %d^k mod %d = %lld (for k multiple of 3)\n", 
           fake_user, MODULUS, attack_token);
    printf("\nAccepted\n");
    printf(">>> Attacker authenticated as ANOTHER user <<<\n");
}

// ============== MAIN PROGRAM ==============
int main() {
    printf("   LAB II - Cryptography and Network Security      \n");
    printf("   Weak Authentication System Analysis             \n");
    
    // Step 1: Setup
    show_system_setup();
    
    // Step 2: Legitimate use
    legitimate_authentication();
    
    // Step 3: Attacker observes
    attacker_passive_capture();
    attacker_gcd_check();
    
    // Step 4: System vulnerability discovered
    system_breaks();
    prime_factorization();
    compute_euler_function();
    
    // Step 5: Token repetition
    demonstrate_token_repetition();
    
    // Step 6: Attacks
    printf("\n");
    printf("    HOW ATTACKER WINS WITHOUT KNOWING k             \n");
 
    
    attack_1_replay();
    attack_2_token_prediction();
    attack_3_impersonation();
    
    // Final summary
    print_section("SUMMARY");
    printf("Composite modulus (n=%d) is BROKEN:\n", MODULUS);
    printf("  ✗ GCD reveals factors\n");
    printf("  ✗ φ(n) = %d (small cycle)\n", euler_totient(MODULUS));
    printf("  ✗ Tokens repeat\n");
    printf("  ✗ All attacks succeed\n");
    printf("\nSOLUTION: Use PRIME modulus\n");
    
    printf("\n\nPress Enter to exit...");
    getchar();
    
    return 0;
}
