#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void encrypt(char *plaintext, char *key, char *ciphertext)
{
  int i, j, offset;
  i = 0;
  j = 0;
  while(plaintext[i] != '\n' && plaintext[i] != '\0')
  {
    offset = key[j] -(int)('a');
    if(plaintext[i] <= 'Z' && plaintext[i] >='A')
    {
      printf("plaintext[%d]=%c \n", i, plaintext[i]);
      char c;
      //printf("i = %d, %c\n", i, plaintext[i]);

      //plaintext[i] = 's';// why it can't work??

      //plaintext[i] = (char)((int)plaintext[i] + 0);
      //c = (char)((int)plaintext[i] + 0);
     // memcpy(&c,&plaintext[i],1);
      //plaintext[i] = c;
      printf("plaintext[%d]=%c \n", i, plaintext[i]);
    }
    ciphertext[i] = (int)('a') + (plaintext[i] - (int)'a' + offset) % 26;
    i++;
    j++;
    if(key[j] == '\n' || key[j] == '\0')
    {
      j = 0;
    }
  }
} 

void get_divisor(char *p);
void get_divisor(char *p)
{
  
}
int get_key_size(char* ciphertext)
{
  int i;
  int m;
  int j, k;
  int len = strlen(ciphertext);
  int *keysize = malloc(sizeof(int)*strlen(ciphertext));
  memset(keysize, 0, sizeof(int)*strlen(ciphertext)); // is possible key size is 27, set keysize[26]=1; 
  //keysize(strlen(keyseize) -1 ) = '\0';
  k = 0; //the count of possible key_size
  for(m = 1; m < len/2 ; m++)
  {
    int block_num = len -m;
    //int *block_start_pos = malloc(sizeof(int)*block_num);
    //for(i = 0; i < block_num; i++)
    //{
    //  block_start_pos[i] = i;
    //}
    for(i = 0; i < block_num; i++)
    {
      char *block_1 = malloc(sizeof(char)*m + 2);
      memset(block_1, '\0', strlen(block_1));
      memcpy(block_1, ciphertext + i, m+1);
      for(j = i + 1 + m; j < block_num; j++)
      {
        if(j >= block_num) break;
        char *block_2 = malloc(sizeof(char)*m + 2);
        memset(block_2, '\0', strlen(block_2));
        memcpy(block_2, ciphertext + j, m+1);
        if(strcmp(block_1, block_2) == 0)
        {
           printf("found same block: %s at %d and %d, size: %d\n", block_1, i, j, j-i);
           keysize[k] = j-i;
           k++;
        }
        free(block_2);
      }
      free(block_1);
    }
    //free(block_start_pos);
  }
  //k = 0;
  //for(i = 0; i< strlen(keysize); i++)
  //{
  //   if(keysize[i] == '1')
  //   {
  //      k++;
  //   }
  //}
  char **ptr = malloc(sizeof(char*)*k);
  for(i = 0; i < k; i++)
  {
     int num = keysize[i];
     ptr[i] = malloc(sizeof(char)*(num + 1));
     memset(ptr[i], '0', num);
     ptr[i][num-1]   = '1' ;
     ptr[i][num] = '\0';
    /* at first, ptr[i] = "00000....001\0", after get_divisor, ptr[i] = "0..1..00..100..1..1\0",
     where 1 means the pos is the divisor number of keysize[i]*/
     get_divisor(ptr[i]);
  }
  //free
  for(i = 0; i < k; i++)
  {
    free(ptr[i]);
  }  
  free(keysize);
  return 0;
}
int main()
{
  char *plaintext = "helloisimaiamveryhappytoliveinthisverybeautifulcampusthisisaverygoodpalce";
  char *ciphertext;
  char *key = "xyz";
  int i;
  ciphertext = malloc(strlen(plaintext) + 1);
  memset(ciphertext, '\0', strlen(ciphertext));
  encrypt(plaintext, key, ciphertext);
  printf("             ");
  for(i = 0; i< strlen(ciphertext); i++)
  {
      printf("%d", i);
  }
  printf("\n");
  printf("plaintext  = %s, key = %s\n", plaintext, key);
  printf("ciphertext = %s\n", ciphertext);
  get_key_size(ciphertext);
  //get_key_size(plaintext);
  free(ciphertext);
  return 0;
}
