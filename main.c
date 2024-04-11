#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#define THRESHOLD 0.005

void printArray(int* arr, int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\t");
    printf("%d   ", arr[32]);
    printf("%d", arr[101]);
    printf("\n");
}

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
        //printf("result: %f \n", result);
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
        //printf("Loop: %d\n", i);
        // 아스키 코드 하나하나씩 사용해서 XOR 을 해보며 분포가 가장 큰 것을 사용
        double max = 0;
        int maxChar;
        for (int k = 0; k < 256; k++) {
            int j = i;
            //printf("Loop: %d %c", k, k);
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
                if (max != 0) {
                    printf("Loop %d : Ascii %d %f\n", i+1, k, sumOfCharDist);
                }
                max = sumOfCharDist;
                maxChar= k;
            }
            free(asciiCnt);
        }
        key[i] = maxChar;
    }
    return key;
}

// todo: 제출 전에 마지막으로 출력하는 부분만 수정하기!!
int main() {
    char ciphertext[10000];
    //FILE *ciphertextFile = fopen("hw1_output.txt", "r");
    FILE *ciphertextFile = fopen("/Users/wonil/study/crypto-vigenere/hw1_input.txt", "r");
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
    //printf("Key len: %d\n", getKeyLen(ciphertext, length));
    int predictedKeyLen = getKeyLen(ciphertext, length);
    int* predictedKey = getKeyChar(ciphertext, length, predictedKeyLen);
    for (int i=0; i< predictedKeyLen; i++) {
        printf("%02x ", predictedKey[i]);
    }
    fclose(ciphertextFile);
    return 0;
}
