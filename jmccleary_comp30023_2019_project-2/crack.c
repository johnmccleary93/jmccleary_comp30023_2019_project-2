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

int hex_to_int(char c){
        int first = c / 16 - 3;
        int second = c % 16;
        int result = first*10 + second;
        if(result > 9) result--;
        return result;
}

int hex_to_ascii(char c, char d){
        int high = hex_to_int(c) * 16;
        int low = hex_to_int(d);
        return high+low;
}

void findPassword4(int bytes[]){
   unsigned char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[{]}|'\";:\\<,.>/?`~";
   //char alphabet[] = "jmcc";
   unsigned char guess[16];
   unsigned char guesshash[256]; //The hash of the guess will be stored here.
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
                   while (((passwordguess * 32) + j) <= 320){
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

void findPassword6(int bytes[]){
   char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[{]}|'\";:<,.>/?";
   //char alphabet[] = "jmccleL[123";
   unsigned char guess[24];
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
                           while (((passwordguess * 32) + j) <= 640){
                               if (j == 32){
                                   printf("%s %d\n", guess, passwordguess + 11);
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

void comparePassword(int passwordints[], int passhashes[]){
    SHA256_CTX ctx;
    unsigned char password[40000];
    unsigned char passwordhash[256];
    int length = 300;
    for (int i = 0; i < length; i++){
        //printf("%d", passwordints[i]);
        password[i] = passwordints[i];
    }
    sha256_init(&ctx);
    sha256_update(&ctx, password, strlen(password));
    sha256_final(&ctx, passwordhash);
    int passwordguess = 0;
    int j = 0;
    while (((passwordguess * 32) + j) <= 30000){
        if(j == 32){
            printf("%s %d\n", password, passwordguess + 1);
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
     int passwordints[40000];
     int count = 0;
     int passhashes[40000];
     
     while ((c = fgetc(fp2)) != EOF){
           passhashes[count] = c;
           count++; 
     }
     count = 0;
     c = 0;  
     while ((c = fgetc(fp1)) != EOF){
           if (c != 13 && c != 10){ 
                passwordints[count] = c; 
                count++;                                 
           }
           else if (c != 10){
               //printf("%d ", c);
                comparePassword(passwordints, passhashes);
                count = 0;
                //memset(passwordints, 0, sizeof(passwordints));
           }
     }
     comparePassword(passwordints, passhashes);
     fclose(fp1);
     fclose(fp2);
     //printf("%c", password[0]);
}


int main(int argc, char * argv[])
{
   int bytes4[320]; // All bytes from pwd4sha256 file
   int bytes6[640]; //All bytes from the pwd6sha256 file
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

