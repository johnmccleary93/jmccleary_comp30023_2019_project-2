#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
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
void findPassword4(int password[], int passnum){
   char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[{]}|'\";:<,.>/?";
   char guess[16];
   unsigned char  guesshash[256]; //The hash of the guess will be stored here.
   SHA256_CTX ctx;
   int charguess1 = 0;
   int charguess2 = 0;
   int charguess3 = 0;
   int charguess4 = 0;
   bool found = false;
   while (!found){   
       while (charguess1 < strlen(alphabet)){
           while (charguess2 < strlen(alphabet)){
               while (charguess3 < strlen(alphabet)){
                   while (charguess4 < strlen(alphabet)){
                       guess[0] = alphabet[charguess1];
                       guess[1] = alphabet[charguess2];
                       guess[2] = alphabet[charguess3];
                       guess[3] = alphabet[charguess4]; 
                       sha256_init(&ctx);
                       sha256_update(&ctx, guess, 4);
                       sha256_final(&ctx, guesshash);
                       int j = 0;
                       while (j < strlen(guesshash)){
                           if (guesshash[j] != password[j]){
                               break;
                           }
                           else{
                               j++;
                           }    
                       }
                       if (j == 32){
                           printf("%s %d\n", guess, passnum + 1);
                           return;
                       }
                       charguess4++;  
                   }
                   charguess3++;
                   charguess4 = 0;
               }
               charguess2++;
               charguess3 = 0;
               charguess4 = 0;
               
           }
           charguess1++;
           charguess2 = 0;
           charguess3 = 0;
           charguess4 = 0;
       }   
   }

}


void getPassword(int bytes[], int password[], int i){
  int passlength = 32;
  for (int j = 0; j < passlength; j++){
      password[j] = bytes[i];
      i = i + 1;
  }
} 
 
int main()
{
   char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[{]}|'\";:<,.>/?";
   //char alphabet[] = "jmcc";
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
   bool found = false;
   int i = 0;
   int passnum = 0;
   
   while ((c = fgetc(fp)) != EOF) {
       bytes[count] = c;
       count++;
   }
   fclose(fp);

   while(passnum < 10){
       bzero(password, 256);
       getPassword(bytes, password, i);
       findPassword4(password, passnum);
       i = i + 32;
       passnum++;
   }
   return 0;
}

