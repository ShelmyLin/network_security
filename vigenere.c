/* Written by Xiongmin Lin <linxiongmin@gmail.com>, ISIMA, Clermont-Ferrand *
 * (c) 2014. All rights reserved.                                           *                                           
 * http://sancy.univ-bpclermont.fr/~guitton/enseignements/admin.html        */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void encrypt(char *plaintext, char *key, char *ciphertext)
{
  int    i   ;
  int    j   ;
  int offset ;
  i =    0   ;
  j =    0   ;
  while(plaintext[i] != '\n' && plaintext[i] != '\0')
  {
    offset = key[j] -(int)('a');
//    if(plaintext[i] <= 'Z' && plaintext[i] >='A')
//    {
//      printf("plaintext[%d]=%c \n", i, plaintext[i]);
//      char c;
//      printf("i = %d, %c\n", i, plaintext[i]);
//      plaintext[i] = 's';// why it can't work??
//      plaintext[i] = (char)((int)plaintext[i] + 0);
//      c = (char)((int)plaintext[i] + 0);
//      memcpy(&c,&plaintext[i],1);
//      plaintext[i] = c;
//      printf("plaintext[%d]=%c \n", i, plaintext[i]);
//    }
    ciphertext[i] = (int)('a') + (plaintext[i] - (int)'a' + offset) % 26;
    i++;
    j++;
    if(key[j] == '\n' || key[j] == '\0')
    {
      j = 0;
    }
  }
} 

void get_divisor(int *p, int num)
{
  int i;
  int j;
  for(i = 3; i < num; i++)
  {
    if(num%i == 0)
    {
      p[i-1] = 1;
      //j = num / i;
      //p[j-1] = 1;
     // printf("get %d %d\n", i , j);
    }
  }
  
}

/* to avoid noice, get_key_size() calculates the weight of each possible keys and the result is    *
 * more precise than get_key_size_02, which just calculates the same divisor of all possible keys */
int get_key_size(char* ciphertext)
{
  int size = 0;
  int i;
  int m;
  int j, k;
  int len = strlen(ciphertext);
  int *keysize = malloc(sizeof(int)*strlen(ciphertext));
  memset(keysize, 0, sizeof(int)*strlen(ciphertext)); // if possible key size is 27, set keysize[26]=1; 
  k = 0; //the count of possible key_size
  for(m = 2; m < len/2 ; m++)
  {
    int block_num = len -m;
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
  }

  /* from code above, we know all possible key sizes (count: k), which are stored in keysize array *
   * if possible key size is 27, then keysize[26]=1;                                               */


  /* get max number of key size, to malloc the array, each possible key size will be split as an   *
   * array ptr[i] and be added with an all-0 array: weight, from the weight of each key, we know   *
   * the most possible keysize                                                                     */
  int **ptr = malloc(sizeof(int*)*k);
  int max = 0;
  for(i = 0; i < k; i++)
  {
     int num = keysize[i];
     max = (max > num)? max : num;
  }

  int *weight = malloc(sizeof(int) * max);
  memset(weight, 0, max);

  for(i = 0; i < k; i++)
  {
     int num = keysize[i];
     ptr[i] = malloc(sizeof(int)*max);
     memset(ptr[i], 0, max);
     ptr[i][num-1]   = 1 ;

     /* at first, ptr[i] = "00000...00100..", after get_divisor, ptr[i] = "0..1..00..100..1..100...", *
     * where 1 means the match pos is the divisor number of keysize[i]                               */
     get_divisor(ptr[i], num);
     for(j = 0; j < max; j++)
     {
       weight[j] = weight[j] + ptr[i][j];
     }
  }
  int max_weight = 0;
  
  for(j = 0; j < max; j++)
  {
    printf("weight of %d: %d\n", j+1, weight[j]);
    if(max_weight < weight[j])
    {
      size = j+1;
      max_weight = weight[j];
    }
  }
  
  for(i = 0; i < k; i++)
  {
    free(ptr[i]);
  }  
  free(keysize);
  free(weight);
  return size;
}



int get_key_size_02(char* ciphertext)
{
  int size = 0;
  int i;
  int m;
  int j, k;
  int len = strlen(ciphertext);
  int *keysize = malloc(sizeof(int)*strlen(ciphertext));
  memset(keysize, 0, sizeof(int)*strlen(ciphertext)); // if possible key size is 27, set keysize[26]=1; 
  k = 0; //the count of possible key_size
  for(m = 1; m < len/2 ; m++)
  {
    int block_num = len -m;
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
  }

  /* from code above, we know all possible key sizes (count: k), which are stored in keysize array *
   * if possible key size is 27, then keysize[26]=1;                                               */


  /* get max number of key size, to malloc the array, each possible key size will be split as an   *
   * array ptr[i] and be compared with an all-1 array: result                                      */
  int **ptr = malloc(sizeof(int*)*k);
  int max = 0;
  for(i = 0; i < k; i++)
  {
     int num = keysize[i];
     max = (max > num)? max : num;
  }

  int *result = malloc(sizeof(int) * max);
  memset(result, 0xff, max);

  for(i = 0; i < k; i++)
  {
     int num = keysize[i];
     ptr[i] = malloc(sizeof(int)*max);
     memset(ptr[i], 0, max);
     ptr[i][num-1]   = 1 ;

  /* at first, ptr[i] = "00000...00100..", after get_divisor, ptr[i] = "0..1..00..100..1..100...", *
   * where 1 means the match pos is the divisor number of keysize[i]                               */
     get_divisor(ptr[i], num);
     for(j = 0; j < max; j++)
     {
       result[j] = result[j] && ptr[i][j];
     }
  }
  for(j = 0; j < max; j++)
  {
    if(result[j] != 0)
      {
        size = j+1;
        //printf("keysize = %d\n", j+1);
      }
  }
  
  for(i = 0; i < k; i++)
  {
    free(ptr[i]);
  }  
  free(keysize);
  free(result);
  return size;
}
void decrypt(char *ciphertext, char *key, char* plaintext)
{
  int    i   ;
  int    j   ;
  int offset ;
  i =    0   ;
  j =    0   ;
  while(ciphertext[i] != '\n' && ciphertext[i] != '\0')
  {
    offset = key[j] -(int)('a');
    if((ciphertext[i] - (int)'a' - offset) < 0)
    {
      plaintext[i] = ciphertext[i] - offset + 26;
    }
    else
    { 
      plaintext[i] = ciphertext[i] - offset;  //it seems that we can't modify plaintext
    }
    i++;
    j++;
    if(key[j] == '\n' || key[j] == '\0')
    {
      j = 0;
    }
  }

}
void modify_plaintext(char *text)
{
  int i, j;
  i = 0;
//  while(text[i] != '\0')
}
int main()
{
  //char *plaintext = "helloisimaiamveryhappytoliveinthisverybeautifulcampusthisisaverygoodplace";// if declare in this way , i can't modify it
  //char plaintext[100] = "helloisimaiamveryhappytoliveinthisverybeautifulcampusthisisaverygoodplace"; // OK
  char *plaintext;
  char *ciphertext;
  char *key;
  int i;
  int keysize;

  printf("please input plaintext \n");
  for(i = 0, plaintext = malloc(1); (*(plaintext + i) = getchar()) != '\n'; i++)
  {
    plaintext = (char*)realloc(plaintext, strlen(plaintext)+1);
  }
  plaintext[i] = '\0';

  printf("please input the key\n");
  for(i = 0,key = (char*)malloc(1); (*(key + i) = getchar()) != '\n'; i++)
  {
    key=(char*)realloc(key,strlen(key)+1);
  }
  *(key+i)='\0';
  
  ciphertext = malloc(strlen(plaintext) + 1);
  memset(ciphertext, '\0', strlen(ciphertext));
  
  encrypt(plaintext, key, ciphertext);
  printf("encrype: plaintext  = %s, key = %s\n", plaintext, key);
  printf("encrype: ciphertext = %s\n", ciphertext);
  
  keysize = get_key_size(ciphertext);
  printf("after calculating, keysize = %d\n",keysize);

  decrypt(ciphertext, key, plaintext);
  printf("decrype: ciphertext = %s, key = %s \n", ciphertext, key);
  printf("decrype: plaintext  = %s\n", plaintext);

  free(ciphertext);
  free(key);
  return 0;
}
