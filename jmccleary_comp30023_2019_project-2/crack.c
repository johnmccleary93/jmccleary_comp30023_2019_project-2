#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
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
void findPassword4(int bytes[], int passnum){
   char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[{]}|'\";:<,.>/?";
   //char alphabet[] = "jmcc";
   char guess[16];
   unsigned char  guesshash[256]; //The hash of the guess will be stored here.
   SHA256_CTX ctx;
   int charguess1 = 0;
   int charguess2 = 0;
   int charguess3 = 0;
   int charguess4 = 0;  
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
                   int passwordguess = 0;
                   int j = 0;
                   while (((passwordguess * 32) + j) < 320){
                       if (j == 32){
                           printf("%s %d\n", guess, passwordguess + 1);
                           fflush(stdout);
                           break;
                       }
                       if (guesshash[j] != bytes[(passwordguess * 32) + j]){
                           passwordguess = passwordguess + 1;
                           j = 0;
                       }
                       else{
                           j++;
                       }    
                   }
                   charguess4++;  
                   passwordguess = 0;
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

void findPassword6(int bytes[], int passnum){
   char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[{]}|'\";:<,.>/?";
   //char alphabet[] = "jmccleL[123";
   char guess[24];
   unsigned char  guesshash[256]; //The hash of the guess will be stored here.
   SHA256_CTX ctx;
   int charguess1 = 0;
   int charguess2 = 0;
   int charguess3 = 0;
   int charguess4 = 0;  
   int charguess5 = 0;
   int charguess6 = 0;
   int passwordguess = 1;
   clock_t begin = clock();
   while (charguess1 < strlen(alphabet)){
       while (charguess2 < strlen(alphabet)){
           while (charguess3 < strlen(alphabet)){
               while (charguess4 < strlen(alphabet)){
                   while (charguess5 < strlen(alphabet)){
                       while (charguess6 < strlen(alphabet)){
                           guess[0] = alphabet[charguess1];
                           guess[1] = alphabet[charguess2];
                           guess[2] = alphabet[charguess3];
                           guess[3] = alphabet[charguess4]; 
                           guess[4] = alphabet[charguess5];
                           guess[5] = alphabet[charguess6];
                           sha256_init(&ctx);
                           sha256_update(&ctx, guess, 6);
                           sha256_final(&ctx, guesshash);
                           int passwordguess = 0; //This checks what password we are currently looking at.
                           int j = 0; //This is what byte of the password we're looking at.
                           while (((passwordguess * 32) + j) < 640){
                               if (j == 32){
                                   printf("%s %d\n", guess, passwordguess + 1);
                                   fflush(stdout);
                                   break;
                               }
                               if (guesshash[j] != bytes[(passwordguess * 32) + j]){
                                   passwordguess = passwordguess + 1;
                                   j = 0;
                               }
                               else{
                                   j++;
                               }    
                           }
                           charguess6++;
                           passwordguess = 0;
                       }
                       charguess5++;
                       charguess6 = 0;
                   }  
                   charguess4++; 
                   charguess5 = 0;
                   charguess6 = 0;
               }
               charguess3++;
               charguess4 = 0;
               charguess5 = 0;
               charguess6 = 0;
           }
           clock_t end2 = clock();
           double time_spend2 = (double) (end2 - begin) / CLOCKS_PER_SEC;         
           printf("%s took %f\n", guess, time_spend2 / 1000.0);             
           charguess2++;
           charguess3 = 0;
           charguess4 = 0;
           charguess5 = 0;
           charguess6 = 0;
       }
       clock_t end = clock();
       double time_spend = (double) (end - begin) / CLOCKS_PER_SEC;
       printf("%s took %f\n", guess, time_spend / 1000.0);
       fflush(stdout);
       charguess1++;
       charguess2 = 0;
       charguess3 = 0;
       charguess4 = 0;
       charguess5 = 0;
       charguess6 = 0;
   }   
}

void getPassword(int bytes[], int password[], int i){
  int passlength = 32;
  for (int j = 0; j < passlength; j++){
      password[j] = bytes[i];
      printf("%02x", password[j]);
      fflush(stdout);
      i = i + 1;
  }
} 
 
void addHashes(int bytes[], char * filepath){
    int c = 0;
    FILE *fp;
    fp = fopen(filepath, "r");
    int count = 0;
    while ((c = fgetc(fp)) != EOF){
        bytes[count] = c;
        count++; 
    }
    fclose(fp);
} 

int main()
{
   char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[{]}|'\";:<,.>/?";
   //char alphabet[] = "jmcc";
   int password[256]; //Each individual password will be stored here.
   int c; 
   //FILE *fp;
   //fp = fopen("/home/jmccleary/pwd4sha256", "r");
   int passlength = 32;
   int bytes4[320]; // All bytes from pwd4sha256 file
   int bytes6[640]; //All bytes from the pwd6sha256 file
   int count = 0; //Count determines where to add all the bytes into the bytes field.
   char guess[16];
   unsigned char  guesshash[256]; //The hash of the guess will be stored here.
   SHA256_CTX ctx;
   bool found = false;
   int i = 64;
   int passnum = 2;
   
   //addHashes(bytes4, "/home/jmccleary/pwd4sha256");
   addHashes(bytes6, "/home/jmccleary/pwd6sha256");
   //findPassword4(bytes4, passnum);
   findPassword6(bytes6, passnum);

   return 0;
}

