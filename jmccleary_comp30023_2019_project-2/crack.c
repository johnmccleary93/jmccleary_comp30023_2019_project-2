#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"
#include "sha256.c"

 void PrintHex(unsigned char * data) 
 {
    char tmp[16];
    for (int i=0; i<32; i++) { 
    sprintf(tmp, "%02x",data[i]); 
    printf("%s",tmp); 
    }
 }
 
 
int main()
{
   char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()";
   int password[256]; //Each individual password will be stored here.
   int c; 
   FILE *fp;
   fp = fopen("/home/jmccleary/pwd4sha256", "r");
   int passlength = 32;
   int bytes[320]; // All bytes from sha256 file
   int count = 0; //Count determines where to add all the bytes into the bytes field.
   char guess[16];
   unsigned char  guesshash[256]; //The hash of the guess will be stored here.
   SHA256_CTX ctx;
 
   
   while ((c = fgetc(fp)) != EOF) {
       bytes[count] = c;
       count++;
   }
   fclose(fp);
   for (int i = 0; i < passlength; i++){
       password[i] = bytes[i+96];
       printf("%02x", bytes[i+96]);
   }
   int i = 0;
   //char guesshashchar[32];
   while(i < 1){
   
       int charguess1 = 0;
       int charguess2 = 0;
       int charguess3 = 0;
       int charguess4 = 0;
       guess[0] = alphabet[charguess1];
       guess[1] = alphabet[charguess2];
       guess[2] = alphabet[charguess3];
       guess[3] = alphabet[charguess4];
       sha256_init(&ctx);
       sha256_update(&ctx, "jmcc", 4);
       sha256_final(&ctx, guesshash);
       
       //Compare each byte of the hashed guess with the password. 
       int j = 0;
       while (j < strlen(guesshash)){
           if (guesshash[j] == password[j]){
               j++;
           }
           else{
               printf("False");
               j++;
           }
       printf("True");
       }
       i++;
   }
   
   sha256_update(&ctx,(unsigned char*)"jmcc",4);
   sha256_final(&ctx,guesshash);
   return 0;
}

