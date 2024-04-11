//
// Created by 최원일 on 2024/04/08.
//
#include <stdio.h>
# define KEY_LENGTH 10 // Can be adjusted from 1 to 15

int encrypt () {
    unsigned char ch ;
    FILE * fpIn , * fpOut ;
    unsigned char key [ KEY_LENGTH ] = { 0x11 , 0x22 , 0x33, 0x44, 0x06 , 0x01 , 0x02 , 0x03, 0x04, 0x05 };
    fpIn = fopen ("/Users/wonil/study/crypto-vigenere/plaintext.txt","r") ;
    if ( fpIn == NULL ) {
        perror ( " Error opening plaintext . txt " ) ;
        return 1;
    }
    fpOut = fopen ("/Users/wonil/study/crypto-vigenere/hw1_input.txt" , "wb") ;
    if ( fpOut == NULL ) {
        perror ( "Error opening hw1_input.txt" ) ;
        fclose ( fpIn ) ;
        return 1;
    }
    for ( int i = 0; fscanf ( fpIn , "%c" , & ch ) != EOF ; ++ i ) {
        ch ^= key [ i % KEY_LENGTH ];
        fwrite (& ch , sizeof ( ch ) , 1 , fpOut ) ;
    }
    fclose ( fpIn ) ;
    fclose ( fpOut ) ;
    return 0;
}

int main() {
    encrypt();
    return 0;
}