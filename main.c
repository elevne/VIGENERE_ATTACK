#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#define THRESHOLD 0.005


int getKeyLen(char *cipherText, int length) {
    int i;
    double *tmp = (double *) malloc(15 * sizeof (double));
    // Key length can be up to 15bytes
    for (i=1; i<=15; i++) {
        int *alphabetCount = (int *) malloc(256 * sizeof (int));
        int j;
        int counter = 0;
        for (int k = 0; k < 256; k++) {
            alphabetCount[k] = 0; // Initialize the counts
        }
        for (j=0; j<=length; j+=i) {
            char c = cipherText[j];
            alphabetCount[c]++;
            counter++;
        }
        int k;
        double result = 0;
        for (k=0; k<256; k++) {
            double t = ((double) alphabetCount[k]/(double) counter);
            result += t*t;
        }
        tmp[i-1] = result;
        free(alphabetCount);
    }
    int x;
    int keyLength = 0;
    double tmpMax = 0;
    for (x=1; x<=15; x++) {
       double xthVal = tmp[x-1];
       if (xthVal > tmpMax + THRESHOLD) {
           tmpMax = xthVal;
           keyLength = x;
       }
    }
    return keyLength;
}

double getSumOfMajorAsciiChars(int *asciiCnt, int cnt) {
    double sum = 0;
    sum += pow((double) asciiCnt[32] / (double) cnt, 2);
    sum += pow((double) asciiCnt[101] / (double) cnt, 2);
    sum += pow((double) asciiCnt[116] / (double) cnt, 2);
    sum += pow((double) asciiCnt[97] / (double) cnt, 2);
    sum += pow((double) asciiCnt[111] / (double) cnt, 2);
    sum += pow((double) asciiCnt[110] / (double) cnt, 2);
    sum += pow((double) asciiCnt[105] / (double) cnt, 2);
    sum += pow((double) asciiCnt[104] / (double) cnt, 2);
    sum += pow((double) asciiCnt[115] / (double) cnt, 2);
    sum += pow((double) asciiCnt[114] / (double) cnt, 2);
    return sum;
}

int* getKeyChar(char* ct, int ctLen, int keyLen) {
    int* key = (int *) malloc(sizeof(int) * keyLen);
    if (key == NULL) {
        printf("MEM ERROR");
        exit(-1);
    }
    int i;
    for (i=0; i<keyLen; i++) {
        // 아스키 코드 하나하나씩 사용해서 XOR 을 해보며 분포가 가장 큰 것을 사용
        double max = 0;
        int maxChar;
        for (int k = 0; k < 256; k++) {
            int j = i;
            // Ciphertext 모든 i 번째 글자를 탐색 (Outer Loop: keyLen 번 분석 수행하는 것)
            int* asciiCnt = (int *) calloc(256, sizeof (int)); // ASCII 등장 횟수 카운트 할 것
            int cnt = 0;
            while (j < ctLen) {
                cnt++;
                char cc = ct[j];
                char ccxor = cc ^ k;
                asciiCnt[ccxor] += 1;
                j += keyLen;
            }
            double sumOfCharDist = getSumOfMajorAsciiChars(asciiCnt, cnt);
            if (sumOfCharDist > max) {
                max = sumOfCharDist;
                maxChar= k;
            }
            free(asciiCnt);
        }
        key[i] = maxChar;
    }
    return key;
}

int main() {
    char ciphertext[10000];
    FILE *ciphertextFile = fopen("./hw1_input.txt", "r");
    if (ciphertextFile == NULL) {
        printf("FAILED TO LOAD CIPHERTEXT");
        return -1;
    }
    int length = 0;
    char c;
    while ((c = fgetc(ciphertextFile)) != EOF && length < sizeof(ciphertext) - 1) {
        ciphertext[length++] = c;
    }
    ciphertext[length] = '\0';
    // 우선 키의 길이를 알아내야 한다.
    int predictedKeyLen = getKeyLen(ciphertext, length);
    int* predictedKey = getKeyChar(ciphertext, length, predictedKeyLen);
    FILE *outputFile = fopen("./hw1_output.txt", "w");
    if (outputFile == NULL) {
        printf("FAILED TO OPEN FILE FOR WRITING");
        return -1;
    }
    for (int i=0; i< predictedKeyLen; i++) {
        fprintf(outputFile,"0x%02x ", predictedKey[i]);
    }
    fprintf(outputFile, "\n");
    unsigned char ch;
    for (int i=0; fscanf(ciphertextFile, "%c", &ch) != EOF; ++ i ) {
        ch ^= predictedKey[i % predictedKeyLen];
        fwrite (&ch, sizeof (ch), 1, outputFile) ;
    }
    fclose(ciphertextFile);
    return 0;
}
