#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#define SHIFT 3
#define MAX_LENGTH 10000
#define NUM_TESTS 20

void caesarEncrypt(char *text, char *result, int shift) {
    strcpy(result, text);
    for (int i = 0; result[i] != '\0'; i++) {
        char ch = result[i];
        if (ch >= 'A' && ch <= 'Z') {
            result[i] = ((ch - 'A' + shift) % 26) + 'A';
        }
        else if (ch >= 'a' && ch <= 'z') {
            result[i] = ((ch - 'a' + shift) % 26) + 'a';
        }
    }
}

void caesarDecrypt(char *text, char *result, int shift) {
    strcpy(result, text);
    for (int i = 0; result[i] != '\0'; i++) {
        char ch = result[i];
        if (ch >= 'A' && ch <= 'Z') {
            result[i] = ((ch - 'A' - shift + 26) % 26) + 'A';
        }
        else if (ch >= 'a' && ch <= 'z') {
            result[i] = ((ch - 'a' - shift + 26) % 26) + 'a';
        }
    }
}

void generateMessage(char *message, int length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i < length; i++) {
        message[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    message[length] = '\0';
}

double bruteForceAttack(char *ciphertext, int length) {
    char *decrypted = (char*)malloc((length + 1) * sizeof(char));
    LARGE_INTEGER frequency, start, end;
    double elapsed;
    
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    
    int shift = 0;
    while (shift < 26) {
        caesarDecrypt(ciphertext, decrypted, shift);
        shift++;
    }
    
    QueryPerformanceCounter(&end);
    elapsed = (double)(end.QuadPart - start.QuadPart) * 1000000.0 / frequency.QuadPart;
    
    free(decrypted);
    return elapsed;
}

int main() {
    char *plaintext, *ciphertext;
    FILE *fp;
    int lengths[NUM_TESTS];
    double times[NUM_TESTS];
    
    printf("=== Caesar Cipher Brute-Force Analysis ===\n\n");
    
    srand(time(NULL));
    
    plaintext = (char*)malloc((MAX_LENGTH + 1) * sizeof(char));
    ciphertext = (char*)malloc((MAX_LENGTH + 1) * sizeof(char));
    
    printf("Testing brute-force attack on varying message lengths...\n\n");
    printf("%-15s %-20s\n", "Message Length", "Time (microseconds)");
    printf("------------------------------------------------\n");
    
    for (int i = 0; i < NUM_TESTS; i++) {
        int length = (i + 1) * (MAX_LENGTH / NUM_TESTS);
        lengths[i] = length;
        
        generateMessage(plaintext, length);
        caesarEncrypt(plaintext, ciphertext, SHIFT);
        
        times[i] = bruteForceAttack(ciphertext, length);
        
        printf("%-15d %-20.2f\n", lengths[i], times[i]);
    }
    
    fp = fopen("bruteforce_data.csv", "w");
    if (fp == NULL) {
        printf("Error opening file for writing\n");
        free(plaintext);
        free(ciphertext);
        return 1;
    }
    
    fprintf(fp, "Message_Length,Time_Microseconds\n");
    for (int i = 0; i < NUM_TESTS; i++) {
        fprintf(fp, "%d,%.2f\n", lengths[i], times[i]);
    }
    fclose(fp);
    
    printf("\n--- Analysis Complete ---\n");
    printf("Data saved to: bruteforce_data.csv\n");
    printf("\nKey Observations:\n");
    printf("1. Time complexity: O(26*n) where n is message length\n");
    printf("2. Only 26 possible keys makes Caesar cipher very weak\n");
    printf("3. Time increases linearly with message length\n");
    printf("\nRun plot_analysis.py to visualize the results.\n");
    
    free(plaintext);
    free(ciphertext);
    
    return 0;
}