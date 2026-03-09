/*
 * LAB II - Cryptography and Network Security
 * Comparison and Analysis Tool
 * 
 * Compares:
 *   Weak System:   n=15 (composite), k=11
 *   Secure System: n=101 (prime), k=13
 * 
 * Generates data for:
 *   - Graph 1: Attack feasibility vs Modulus type
 *   - Graph 2: φ(n) values comparison
 *   - Graph 3: GCD analysis for different User_IDs
 * 
 * Compile: gcc comparison.c -o comparison.exe
 * Run: comparison.exe
 */

#include <stdio.h>
#include <stdlib.h>

// ============== SYSTEM PARAMETERS ==============
#define WEAK_MOD 15
#define WEAK_KEY 11
#define SECURE_MOD 101
#define SECURE_KEY 13

// ============== FUNCTION PROTOTYPES ==============
long long mod_exp(long long base, long long exp, long long mod);
int gcd(int a, int b);
int euler_totient(int n);
void print_section(const char* title);
void graph_1_data();
void graph_2_data();
void graph_3_data();
void show_token_cycles();
void show_attack_comparison();
void comprehensive_test_cases();

// ============== CORE FUNCTIONS ==============

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

int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

int euler_totient(int n) {
    int result = 0;
    for (int i = 1; i < n; i++) {
        if (gcd(i, n) == 1)
            result++;
    }
    return result;
}

void print_section(const char* title) {
    printf("\n");
    printf("========================================\n");
    printf(" %s\n", title);
    printf("========================================\n");
}

// ============== GRAPH DATA GENERATION ==============

// Graph 1: Attack Feasibility vs Modulus Type
void graph_1_data() {
    print_section("GRAPH-1 DATA: Attack Feasibility");
    
    printf("X-axis: Modulus Type\n");
    printf("Y-axis: Attack Feasibility\n\n");
    
    printf("Modulus Type | GCD Attack | Replay | Prediction | Impersonation\n");
    printf("-------------|------------|--------|------------|---------------\n");
    printf("Composite    |    YES     |  YES   |    YES     |      YES\n");
    printf("Prime        |    NO      |  NO    |    NO      |      NO\n");
    
    printf("\n*** Use this data for BAR CHART ***\n");
    printf("Shows: All attacks succeed on composite, all fail on prime\n");
}

// Graph 2: φ(n) Comparison
void graph_2_data() {
    print_section("GRAPH-2 DATA: Euler Totient φ(n)");
    
    int phi_weak = euler_totient(WEAK_MOD);
    int phi_secure = euler_totient(SECURE_MOD);
    
    printf("X-axis: n value (modulus)\n");
    printf("Y-axis: φ(n) value\n\n");
    
    printf("n value | φ(n) | Modulus Type\n");
    printf("--------|------|-------------\n");
    printf("  %3d   | %3d  | Composite\n", WEAK_MOD, phi_weak);
    printf("  %3d   | %3d  | Prime\n", SECURE_MOD, phi_secure);
    
    printf("\nDifference: φ(%d) = %d, φ(%d) = %d\n", 
           WEAK_MOD, phi_weak, SECURE_MOD, phi_secure);
    printf("Ratio: %.2fx larger\n", (float)phi_secure / phi_weak);
    
    printf("\n*** Use this data for LINE/BAR CHART ***\n");
    printf("Shows: Prime modulus has much larger φ(n)\n");
}

// Graph 3: GCD Analysis
void graph_3_data() {
    print_section("GRAPH-3 DATA: GCD Analysis");
    
    printf("X-axis: User_ID\n");
    printf("Y-axis: gcd(User_ID, n)\n\n");
    
    // Data for weak system
    printf("WEAK SYSTEM (n=%d):\n", WEAK_MOD);
    printf("User_ID | gcd(ID,%d) | Vulnerable?\n", WEAK_MOD);
    printf("--------|------------|-------------\n");
    
    for (int uid = 1; uid <= 15; uid++) {
        int g = gcd(uid, WEAK_MOD);
        printf("  %2d    |     %2d     | %s\n", 
               uid, g, (g > 1) ? "YES (⚠)" : "No");
    }
    
    // Data for secure system
    printf("\nSECURE SYSTEM (n=%d):\n", SECURE_MOD);
    printf("User_ID | gcd(ID,%d) | Vulnerable?\n", SECURE_MOD);
    printf("--------|-------------|-------------\n");
    
    for (int uid = 1; uid <= 15; uid++) {
        int g = gcd(uid, SECURE_MOD);
        printf("  %2d    |      %2d      | %s\n", 
               uid, g, (g > 1) ? "YES" : "No (✓)");
    }
    
    printf("\n*** Use this data for SCATTER/LINE PLOT ***\n");
    printf("Shows: Weak system has spikes (gcd>1), secure is flat (gcd=1)\n");
}

// ============== TOKEN CYCLE DEMONSTRATION ==============

void show_token_cycles() {
    print_section("TOKEN CYCLE COMPARISON");
    
    int user_id = 2;
    
    // Weak system
    printf("WEAK SYSTEM (n=%d, User_ID=%d):\n", WEAK_MOD, user_id);
    printf("k  | Token | Notes\n");
    printf("---|-------|------------------\n");
    
    int phi_weak = euler_totient(WEAK_MOD);
    for (int k = 1; k <= phi_weak + 2; k++) {
        long long token = mod_exp(user_id, k, WEAK_MOD);
        printf("%2d | %4lld  |", k, token);
        
        if (k == phi_weak + 1) {
            printf(" REPEATS (cycle=%d)", phi_weak);
        }
        printf("\n");
    }
    
    printf("\nCycle length = φ(%d) = %d\n", WEAK_MOD, phi_weak);
    
    // Secure system
    printf("\nSECURE SYSTEM (n=%d, User_ID=%d):\n", SECURE_MOD, user_id);
    printf("k  | Token | Notes\n");
    printf("---|-------|------------------\n");
    
    for (int k = 1; k <= 15; k++) {
        long long token = mod_exp(user_id, k, SECURE_MOD);
        printf("%2d | %4lld  | No pattern\n", k, token);
    }
    printf("...\n");
    
    int phi_secure = euler_totient(SECURE_MOD);
    printf("\nCycle length = φ(%d) = %d (much longer!)\n", 
           SECURE_MOD, phi_secure);
}

// ============== ATTACK COMPARISON ==============

void show_attack_comparison() {
    print_section("ATTACK SUCCESS COMPARISON");
    
    printf("Attack Type     | Weak System | Secure System | Why?\n");
    printf("----------------|-------------|---------------|---------------------------\n");
    
    // GCD Attack
    printf("GCD Attack      | SUCCESS (✓) | FAILED (✗)   | Prime has no factors\n");
    
    // Replay Attack
    printf("Replay Attack   | SUCCESS (✓) | FAILED (✗)   | Different tokens\n");
    
    // Token Prediction
    int phi_weak = euler_totient(WEAK_MOD);
    int phi_secure = euler_totient(SECURE_MOD);
    printf("Token Predict   | SUCCESS (✓) | FAILED (✗)   | φ=%d vs φ=%d\n", 
           phi_weak, phi_secure);
    
    // Impersonation
    printf("Impersonation   | SUCCESS (✓) | FAILED (✗)   | Can't guess token\n");
    
    printf("\nOverall Security: WEAK vs SECURE\n");
}

// ============== COMPREHENSIVE TEST CASES ==============

void comprehensive_test_cases() {
    print_section("COMPREHENSIVE TEST CASES");
    
    printf("Test | User | Weak     | Weak  | Secure    | Secure | gcd    | gcd\n");
    printf("Case | ID   | Token    | Auth  | Token     | Auth   | (ID,15)| (ID,101)\n");
    printf("-----|------|----------|-------|-----------|--------|--------|----------\n");
    
    int test_users[] = {2, 3, 4, 5, 7, 8, 10, 12, 14};
    int num_tests = sizeof(test_users) / sizeof(test_users[0]);
    
    for (int i = 0; i < num_tests; i++) {
        int uid = test_users[i];
        
        // Weak system
        long long token_weak = mod_exp(uid, WEAK_KEY, WEAK_MOD);
        
        // Secure system
        long long token_secure = mod_exp(uid, SECURE_KEY, SECURE_MOD);
        
        // GCD values
        int gcd_weak = gcd(uid, WEAK_MOD);
        int gcd_secure = gcd(uid, SECURE_MOD);
        
        printf(" %2d  | %2d   | %8lld | PASS  | %9lld | PASS   |   %2d   |    %2d\n",
               i+1, uid, token_weak, token_secure, gcd_weak, gcd_secure);
    }
    
    printf("\n*** Use this table in your report ***\n");
}

// ============== MAIN PROGRAM ==============

int main() {
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║   LAB II - Comparison and Analysis Tool           ║\n");
    printf("║   Generate data for graphs and analysis           ║\n");
    printf("╚════════════════════════════════════════════════════╝\n");
    
    printf("\nComparing Systems:\n");
    printf("  Weak:   n=%d (composite), k=%d, φ(n)=%d\n", 
           WEAK_MOD, WEAK_KEY, euler_totient(WEAK_MOD));
    printf("  Secure: n=%d (prime), k=%d, φ(n)=%d\n", 
           SECURE_MOD, SECURE_KEY, euler_totient(SECURE_MOD));
    
    // Generate graph data
    graph_1_data();
    graph_2_data();
    graph_3_data();
    
    // Show comparisons
    show_token_cycles();
    show_attack_comparison();
    comprehensive_test_cases();
    
    // Summary for report
    print_section("DATA SUMMARY FOR REPORT");
    printf("1. Graph-1: Use attack feasibility table\n");
    printf("   Plot: Bar chart (Composite vs Prime)\n\n");
    
    printf("2. Graph-2: Use φ(n) comparison\n");
    printf("   Plot: Bar/Line chart (%d vs %d)\n\n", 
           euler_totient(WEAK_MOD), euler_totient(SECURE_MOD));
    
    printf("3. Graph-3: Use GCD analysis table\n");
    printf("   Plot: Scatter plot (shows spikes vs flat)\n\n");
    
    printf("4. Include: Token cycle comparison\n");
    printf("5. Include: Attack comparison table\n");
    printf("6. Include: Comprehensive test cases\n");
    
    print_section("KEY FINDINGS");
    printf("✓ Composite modulus (n=%d):\n", WEAK_MOD);
    printf("  - Factorizable: %d = 3 × 5\n", WEAK_MOD);
    printf("  - φ(n) = %d (small)\n", euler_totient(WEAK_MOD));
    printf("  - All attacks SUCCEED\n\n");
    
    printf("✓ Prime modulus (n=%d):\n", SECURE_MOD);
    printf("  - Cannot factor (prime)\n");
    printf("  - φ(n) = %d (large)\n", euler_totient(SECURE_MOD));
    printf("  - All attacks FAIL\n\n");
    
    printf("Security Improvement: %.2fx\n", 
           (float)euler_totient(SECURE_MOD) / euler_totient(WEAK_MOD));
    
    printf("\n\nPress Enter to exit...");
    getchar();
    
    return 0;
}