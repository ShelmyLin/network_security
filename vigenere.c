/* Written by Xiongmin Lin <linxiongmin@gmail.com>, ISIMA, Clermont-Ferrand *
 * (c) 2014. All rights reserved.                                           *                                           
 * http://sancy.univ-bpclermont.fr/~guitton/enseignements/admin.html        */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Same_Str{
  char str[1000];
  int  num;
  int  start[1000];
  int  end[1000];
};

void convert(char *origintext, char *plaintext)
{
  int i, j;
  i = 0;
  j = 0;
  memset(plaintext, '\0', strlen(plaintext));
  while(origintext[i] != '\0')
  {
    if(origintext[i] <= 'Z' && origintext[i] >= 'A')
    {
      plaintext[j] = origintext[i] + 32;
      j++;
    }
    if(origintext[i] <= 'z' && origintext[i] >= 'a')
    {
      plaintext[j] = origintext[i];
      j++;
    }
    i++;
  }
  
}
void get_freq(char *plaintext, double m_fre[26])
{
  int i, pos;
  int count;
  count = strlen(plaintext);
  for(i = 0; i < 26; i++)
  {
    m_fre[i] = 0;
  }
  i = 0;
  while(plaintext[i] != '\0')
  {
    pos = (int)(plaintext[i] - 'a');
    m_fre[pos]++;
    i++;
  }
  
  for(i = 0; i < 26; i++)
  {

    m_fre[i] = m_fre[i] / (double)count;
  }

}
void show_freq(double m_fre[26])
{
  int i;
  printf("-------------------------------------------\n");
//  printf("frequency of plaintext: \n");
  for(i = 0; i < 26; i++)
  {
    char c = (char)(i + (int)('a'));
    printf("-> %c: %f%%\n", c, m_fre[i] * 100);
  }
  printf("-------------------------------------------\n");
}
void encrypt(char *plaintext, char *key, char *ciphertext)
{
  int    i   ;
  int    j   ;
  int offset ;
  i =    0   ;
  j =    0   ;

  while( plaintext[i] != '\n' &&
         plaintext[i] != '\0'   )
  {
    offset = key[j] -(int)('a');

    if(  plaintext[i] <= 'Z'  &&
         plaintext[i] >='A'     )
    {
      plaintext[i] = plaintext[i] + 32 ;
    }
    ciphertext[i] = (int)('a') + (plaintext[i] - (int)'a' + offset) % 26;
    i++;
    j++;
    if( key[j] == '\n' ||
        key[j] == '\0'   )
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
    }
  }
  
}

/* to avoid noice, get_key_size() calculates the weight of each possible keys and the result is    *
 * more precise than get_key_size_02, which just calculates the same divisor of all possible keys */
/* the way i was used to calculate the weight was wrong, i should calculate the weight of same blocks, *
 * not divisors*/
int get_key_size(char* ciphertext)
{
  int size = 0;
  int i, j, m, k, r;
  int len = strlen(ciphertext);
  int *keysize = malloc(sizeof(int)*strlen(ciphertext));
  memset(keysize, 0, sizeof(int)*strlen(ciphertext));    // if possible key size is 27, set keysize[26]=1; 
  int malloc_size = 1000;
  struct Same_Str *same_str = malloc(sizeof(struct Same_Str) * malloc_size);
  int str_num;
  str_num = 0;
  for(i = 0; i < malloc_size; i++)
  {
    same_str[i].num = 0;
  }
   
  char *block_1 = malloc(len);
  char *block_2 = malloc(len);
  for(m = 2; m < len/2 ; m++)
  {
    int block_num = len -m;
    for(i = 0; i < block_num; i++)
    {
      memset(block_1, '\0', strlen(block_1));
      memcpy(block_1, ciphertext + i, m+1);
      int w = 0;                                           // weight
      for(j = i + 1 + m; j < block_num; j++)
      {
        if(j >= block_num) break;
        memset(block_2, '\0', strlen(block_2));
        memcpy(block_2, ciphertext + j, m+1);
        if(strcmp(block_1, block_2) == 0)
        {
           w++;
        
           int pos = same_str[str_num].num;
           same_str[str_num].start[pos] = i;
           same_str[str_num].end[pos]   = j;
           same_str[str_num].num++;

        }
      }
      if(w > 0)
      {
        sprintf(same_str[str_num].str, "%s", block_1);
        printf("No.%d, found same block: %s, %d times\n",str_num, same_str[str_num].str, same_str[str_num].num);
        str_num++;
        if(str_num >= malloc_size)
        {
          malloc_size += 1000;
          same_str = realloc(same_str, sizeof(struct Same_Str) * malloc_size);
        }
    
      }
      //usleep(100);
    }
  }

  free(block_1);
  free(block_2);



  /* from code above, we know all possible key sizes (count: str_num), which are stored in same_str array */

  /*if some strs whose replication time is more than 2, then it must be the REAL str*/
  k = 0;
  for(m = 0; m < str_num; m++ )
  {
    if(same_str[m].num >= 2)
    {
      /*the REAL str*/
      for(r = 0; r < same_str[m].num; r++)
      {
        int start  = same_str[m].start[r];
        int end    = same_str[m].end[r];
      	keysize[k] = end - start;
        k++;          
      }
    }
    else
    {
    
    }
  
  }


  /* get max number of key size, to malloc the array, each possible key size will be split as an   *
   * array ptr[i] and be added with an all-0 array: weight, from the weight of each key, we know   *
   * the most possible keysize                                                                     */
  int **ptr = malloc(sizeof(int*)*k);
  int max   = 0;
  for(i = 0; i < k; i++)
  {
     int num = keysize[i];
     max     = (max > num)? max : num;
  }

  int *weight = malloc(sizeof(int) * max);
  for(i = 0; i < max ;i++)
  {
    weight[i] = 0;
  }
  for(i = 0; i < k; i++)
  {
     int num       = keysize[i];
     ptr[i]        = malloc(sizeof(int)*max);
     ptr[i][num-1] = 1 ;
     memset(ptr[i], 0, max);

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
    if(weight[j] != 0)
    {
      printf("weight of %d: %d\n", j+1, weight[j]);
    }
    if(max_weight < weight[j])
    {
      size       = j+1;
      max_weight = weight[j];
    }
  }
  
  for(i = 0; i < k; i++)
  {
    free(ptr[i]);
  }  
  free(keysize);
  free(weight);
  free(ptr);
  free(same_str);
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
int main()
{
  //char *plaintext = "helloisimaiamveryhappytoliveinthisverybeautifulcampusthisisaverygoodplace";// if declare in this way , i can't modify it
  //char plaintext[100] = "helloisimaiamveryhappytoliveinthisverybeautifulcampusthisisaverygoodplace"; // OK
  char *origintext;
  char *plaintext;
  char *ciphertext;
  char *key;
  double fre[26];
  int i;
  int keysize;
  origintext = (char*) malloc(1000);
  printf("please input origin text \n");
  for(i = 0; (*(origintext + i) = getchar()) != '\n'; i++)
  {
    if((i+1) % 1000 == 0)
    {
      origintext = (char*)realloc(origintext, strlen(origintext) + 1000);
    }
    
  }
  origintext[i] = '\0';
  plaintext = (char*)malloc(strlen(origintext));   
  memset(plaintext, '\0', strlen(plaintext));
  convert(origintext, plaintext);
  get_freq(plaintext, fre);
  printf("frequency of plaintext: \n");
  show_freq(fre);

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

  get_freq(ciphertext, fre);
  printf("frequency of ciphertext: \n");
  show_freq(fre);


  
  keysize = get_key_size(ciphertext);
  printf("after calculating, keysize = %d\n",keysize);

  decrypt(ciphertext, key, plaintext);
  printf("decrype: ciphertext = %s, key = %s \n", ciphertext, key);
  printf("decrype: plaintext  = %s\n", plaintext);
  
  free(origintext);
  free(plaintext);  
  free(ciphertext);
  free(key);
  return 0;
}
