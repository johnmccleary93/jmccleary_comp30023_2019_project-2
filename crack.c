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
    for (size_t i=0; i<32; i++) { 
    sprintf(tmp, "%02x",data[i]); 
    printf("%s",tmp); 
    }
 }

size_t hex_to_size_t(char c){
        size_t first = c / 16 - 3;
        size_t second = c % 16;
        size_t result = first*10 + second;
        if(result > 9) result--;
        return result;
}

size_t hex_to_ascii(char c, char d){
        size_t high = hex_to_size_t(c) * 16;
        size_t low = hex_to_size_t(d);
        return high+low;
}

void findPassword4(size_t bytes[]){
   unsigned char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[{]}|'\";:\\<,.>/?`~";
   //char alphabet[] = "jmcc";
   unsigned char guess[16];
   unsigned char guesshash[256]; //The hash of the guess will be stored here.
   SHA256_CTX ctx;
   size_t charguess1 = 0;
   size_t charguess2 = 0;
   size_t charguess3 = 0;
   size_t charguess4 = 0;  
   while (charguess1 < strlen((const char*) alphabet)){
       while (charguess2 < strlen((const char*) alphabet)){
           while (charguess3 < strlen((const char*) alphabet)){
               while (charguess4 < strlen((const char*) alphabet)){
                   guess[0] = alphabet[charguess1];
                   guess[1] = alphabet[charguess2];
                   guess[2] = alphabet[charguess3];
                   guess[3] = alphabet[charguess4]; 
                   sha256_init(&ctx);
                   sha256_update(&ctx, guess, 4);
                   sha256_final(&ctx, guesshash);
                   size_t passwordguess = 0;
                   size_t j = 0;
                   while (((passwordguess * 32) + j) <= 320){
                       if (j == 32){
                           printf("%s %ld\n", guess, passwordguess + 1);
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

void findPassword6(size_t bytes[]){
   unsigned char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[{]}|'\";:<,.>/?";
   //char alphabet[] = "jmccleL[123";
   unsigned char guess[24];
   unsigned char guesshash[256]; //The hash of the guess will be stored here.
   SHA256_CTX ctx;
   size_t charguess1 = 0;
   size_t charguess2 = 0;
   size_t charguess3 = 0;
   size_t charguess4 = 0;  
   size_t charguess5 = 0;
   size_t charguess6 = 0;
   clock_t begin = clock();
   while (charguess1 < strlen((const char*) alphabet)){
       while (charguess2 < strlen((const char*) alphabet)){
           while (charguess3 < strlen((const char*) alphabet)){
               while (charguess4 < strlen((const char*) alphabet)){
                   while (charguess5 < strlen((const char*) alphabet)){
                       while (charguess6 < strlen((const char*) alphabet)){
                           guess[0] = alphabet[charguess1];
                           guess[1] = alphabet[charguess2];
                           guess[2] = alphabet[charguess3];
                           guess[3] = alphabet[charguess4]; 
                           guess[4] = alphabet[charguess5];
                           guess[5] = alphabet[charguess6];
                           sha256_init(&ctx);
                           sha256_update(&ctx, guess, 6);
                           sha256_final(&ctx, guesshash);
                           size_t passwordguess = 0; //This checks what password we are currently looking at.
                           size_t j = 0; //This is what byte of the password we're looking at.
                           while (((passwordguess * 32) + j) <= 640){
                               if (j == 32){
                                   printf("%s %ld\n", guess, passwordguess + 11);
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

void getPassword(size_t bytes[], size_t password[], size_t i){
  size_t passlength = 32;
  for (size_t j = 0; j < passlength; j++){
      password[j] = bytes[i];
      printf("%02lx", password[j]);
      fflush(stdout);
      i = i + 1;
  }
} 
 
void addHashes(size_t bytes[], char * filepath){
    int c = 0;
    FILE *fp;
    fp = fopen(filepath, "r");
    size_t count = 0;
    while ((c = fgetc(fp)) != EOF){
        bytes[count] = c;
        count++; 
    }
    fclose(fp);
} 

void comparePassword(size_t passwordsize_ts[], size_t passhashes[]){
    SHA256_CTX ctx;
    unsigned char password[40000];
    unsigned char passwordhash[256];
    size_t length = 300;
    for (size_t i = 0; i < length; i++){
        //printf("%ld", passwordsize_ts[i]);
        password[i] = passwordsize_ts[i];
    }
    sha256_init(&ctx);
    sha256_update(&ctx, password, strlen((const char*) password));
    sha256_final(&ctx, passwordhash);
    size_t passwordguess = 0;
    size_t j = 0;
    while (((passwordguess * 32) + j) <= 30000){
        if(j == 32){
            printf("%s %ld\n", password, passwordguess + 1);
            fflush(stdout);
            break;    
            }
        else if(passwordhash[j] != passhashes[(passwordguess * 32) + j]){
            //printf("Password guess is %02x Hash guess is %02x\n", passwordhash[j], passhashes[(passwordguess * 32) + j]);
            passwordguess = passwordguess + 1;
            j = 0;
        }
        else{
            j++;
        } 
    }     
} 

void crack2(char * filepath1, char * filepath2){
     int c = 0;
     FILE *fp1;
     FILE *fp2;
     fp1 = fopen(filepath1, "r");
     fp2 = fopen(filepath2, "r");
     size_t passwordsize_ts[40000];
     size_t count = 0;
     size_t passhashes[40000];
     
     while ((c = fgetc(fp2)) != EOF){
           passhashes[count] = c;
           count++; 
     }
     count = 0;
     c = 0;  
     while ((c = fgetc(fp1)) != EOF){
           if (c != 13 && c != 10){ 
                passwordsize_ts[count] = c; 
                count++;                                 
           }
           else if (c != 10){
               //prsize_tf("%d ", c);
                comparePassword(passwordsize_ts, passhashes);
                count = 0;
                //memset(passwordsize_ts, 0, sizeof(passwordsize_ts));
           }
     }
     comparePassword(passwordsize_ts, passhashes);
     fclose(fp1);
     fclose(fp2);
     //prsize_tf("%c", password[0]);
}


int main(int argc, char * argv[])
{
   size_t bytes4[320]; // All bytes from pwd4sha256 file
   size_t bytes6[640]; //All bytes from the pwd6sha256 file
   if (argc == 1) {
       addHashes(bytes4, "/home/jmccleary/pwd4sha256");
       addHashes(bytes6, "/home/jmccleary/pwd6sha256");
       findPassword4(bytes4);
       findPassword6(bytes6);
   }
   else if (argc == 3){
       crack2(argv[1], argv[2]);
   }
   return 0;
}

