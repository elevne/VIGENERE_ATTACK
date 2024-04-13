## Cryptanalysis of Vigenere Cipher
<div style="text-align: right">-2018311692 최원일</div>

Vigenere Cipher을 통해 암호화된 Ciphertext를 분석할 수 있습니다.
main.c 파일만 컴파일하여 실행하시면 됩니다 (GCC). 분석할 ciphertext의 txt 파일은 실행파일과 동일한 디렉토리에 hw1_input.txt 로 두시면 됩니다. 
결과분석 파일(hw1_output.txt)은 동일한 디렉토리에 저장됩니다.

### 코드 설명

#### 1. Key 길이 분석
키가 무엇인지 분석하기 전에 먼저, Vigenere Cipher Encryption에 사용된 키의 길이를 분석해야 합니다. 과제 조건에서 주어졌듯이 Key의 길이는 1~15 사이라고 가정합니다. 
저의 경우에는, Ciphertext에 대해 각 키 길이에 대한 분석을 한 번씩 진행하였습니다. 즉, 키의 길이를 알아보기 위해 반복을 1~15, 15 번 한 것입니다. 매 반복에서 키의 길이를 i라고 하였을 때,
ciphertext 내의 매 i 번째 character를 조회하고, 각 character의 빈도수, 출현 비율을 체크합니다. 등장한 모든 캐릭터에 대한 출현 비율을 제곱한 값을 모두 더했을 때 그 값이 최대값이 되는 
i를 key의 길이로 결정하였습니다.

```
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
```

이 때, 키 길이의 배수에 대해서도 출현비율의 합이 거의 동일하게 나오는 문제가 발생하였습니다. (e.g., 실제 키 길이가 3이면 예측 시 6, 9, 12, 15 키 길이에 대해서도 높은 출현빈도 제곱합 값을 보임)
이에 대한 완벽한 해결책을 찾지는 못했지만, 지속적으로 다른 키 길이, 다른 키 값, 다른 Plaintext로 테스트해보며 임의의 Threshold 값을 설정하였습니다. (만약 키길이 i의 출현빈도 제곱합이 '기존최대값 + Threshold' 를 넘지 못한다면 Pass하는 방식)

위 키 길이 분석함수는 매 반복문마다 (Ciphertext의 크기 / 예측 키 값) 번, 그리고 출현비율의 합을 구하는 256 번의 Operation이 수행됩니다. 고로 O(N)의 시간복잡도를 갖는다고 할 수 있겠습니다.

#### 2. Key 분석
그 다음으로는 키의 내용을 본격적으로 파악해야 합니다. 앞서 키의 길이를 알아보았습니다. 이를 i 라고 할 때, 이번에도 위 스텝과 비슷하게 i 번의 반복문이 실행됩니다.
텍스트의 0 번 index부터 시작하여, 매 i 번째 캐릭터는 같은 캐릭터로 XOR이 암호화가 진행되었을 것입니다. 고로, 0~i-1 범위의 반복을 돌며 매 i 번째 character마다
키 캐릭터를 예측하면 되는 것입니다. 

이 때는 아래 함수를 작성하여 사용했습니다.
```
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
```
ASCII 캐릭터 중 가장 많이 등장하는 상위 10개의 캐릭터의 출현빈도 제곱값을 더하는 함수입니다. (whitespace, e, i, etc...) 모든 캐릭터에 대해서 할 수도 있겠지만, 
캐릭터의 출현빈도를 보았을 때 상위 10개의 캐릭터에 대해서만 수행해주어도 충분하다고 생각하였습니다.

매 반복마다 256 번의 Guessing을 진행합니다. (i번째 key char: 0x00~0xFF) 각 char 마다 위 함수를 사용하여 출현빈도 제곱값을 구하고, 그 값이 최대가 될 때의
캐릭터를 사용하면 됩니다. 

위 Step 2는 키의 길이만큼, 256번씩, (ciphertext길이 / key길이) 번의 Operation을 수행합니다. O(N)의 시간복잡도를 갖습니다.