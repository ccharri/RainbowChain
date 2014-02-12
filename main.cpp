// John Norwood
// Chris Harris
// EECS 588
// main.cpp

#include "Rainbow_table.h"
#include <openssl/sha.h>   // SHA256
#include <cctype>          // isalphanum
#include <iostream>

using std::vector; using std::string;
using std::cout; using std::endl;


// SHA Rainbow Table params
const size_t MAX_KEY_LENGTH = 8;
const size_t SHA_OUTPUT_LEN = 20;
const size_t NUM_ROWS       = 10000;
const size_t CHAIN_LENGTH   = 1000;
const size_t CHARSET_SIZE   = 512;
const string CHARACTER_SET  = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";


// A character set struct that just wraps an input set of characters as
// many times as it can in a buffer of the templated size.
// This allows us to reduce a number of lg(SIZE) bits to one byte
template <size_t SIZE>
struct Charset
{
  // Wrap the input string of character into our internal buffer as many
  // times as possible
  Charset(const string & character_str)
  {
    size_t begin = 0, end = SIZE;
    while (begin < end)
    {
      for (size_t i = 0; i < character_str.length() + 1 && i < end; ++i)
        charset[begin++] = character_str[i % (character_str.length() + 1)];
  
      for (size_t i = 0; i < character_str.length() + 1 && end - i > begin; ++i)
        charset[end--]   = character_str[i % (character_str.length() + 1)];
    }
  }

  
  // Reduces the input index to single byte by indexing our
  // internal character set buffer
  const char & operator [](size_t index)
  {
    return charset[index % SIZE];
  }


  private:

    char charset[SIZE];
};
  

void naive_redux_func(char key[MAX_KEY_LENGTH], const char * digest, size_t step)
{
  size_t idx = 0;

  for (const char * dig_ptr = digest; dig_ptr < (digest + SHA_OUTPUT_LEN) && idx < MAX_KEY_LENGTH; ++dig_ptr)
  {
    char val = (*dig_ptr) + step; 

    if (isalnum(val))
      key[idx++] = val;
  }

  if (idx < MAX_KEY_LENGTH)
    key[idx] = '\0';
}


// This function reduces a 20 byte SHA hash to an 8 byte key
// It works by splitting up the hash into 8 2 byte chunks, salting
// with the input step, and using them to lookup a byte in the charset
// table
void cryptohaze_redux_func(char key[MAX_KEY_LENGTH], const char * digest, size_t step)
{
  static Charset <CHARSET_SIZE> CHARSET(CHARACTER_SET);

  for (size_t i = 0; i < MAX_KEY_LENGTH; ++i)
  {
    // Point to the ith 2 byte chunk in the hash
    uint16_t chunk = *(const uint16_t *) (digest + 2 * i);

    // For each byte in the chunk, add the step 
    for (size_t i = 0; i < sizeof(uint16_t); ++i)
      ((char *) &chunk)[i] += step;
    
    key[i] = CHARSET[chunk];
  }
}


// The cipher function we're trying to reverse
void SHA_CIPHER_FN(char digest[SHA_OUTPUT_LEN], const char * key)
{
  SHA1((const unsigned char *) key, strnlen(key, MAX_KEY_LENGTH), (unsigned char *) digest);
}


int main()
{
  Rainbow_table <NUM_ROWS, CHAIN_LENGTH, naive_redux_func, MAX_KEY_LENGTH, SHA_CIPHER_FN, SHA_OUTPUT_LEN> 
    rtable(CHARACTER_SET);
}
