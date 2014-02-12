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
const size_t SHA_OUTPUT_LEN = 32;
const size_t NUM_ROWS       = 10000;
const size_t CHAIN_LENGTH   = 100;
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
    for (size_t i = 0; i < SIZE; ++i)
      charset[i] = character_str[i % character_str.length()];
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
  


// Generate the list of keys that will be used to start the chains in the rainbow table
vector <string> generate_keys()
{
  vector <size_t> indices(CHARACTER_SET.size(), 0);
  vector <string> keys(NUM_ROWS);

  for (size_t i = 0; i < NUM_ROWS; ++i)
  {
    bool increment = true;

    for (size_t j = 0; j < CHARACTER_SET.size(); ++j)
    {
      keys[i].push_back(CHARACTER_SET[indices[j]]);
      if (increment)
      {
        increment  = indices[j] == CHARACTER_SET.size()-1;
        indices[j] = increment ? 0 
                               : indices[j] + 1;
      }
    }
  }

  return keys;
}

    
// This function reduces a 32 byte SHA hash to an 8 byte key
// It works by splitting up the hash into 8 4 byte chunks, salting
// with the input step, and using them to lookup a byte in the charset
// table
void redux_func(char key[MAX_KEY_LENGTH], const char * digest, size_t step)
{
  static Charset <CHARSET_SIZE> CHARSET(CHARACTER_SET);

  for (size_t i = 0; i < MAX_KEY_LENGTH; ++i)
  {
    // Point to the ith 4 byte chunk in the hash
    const uint32_t * chunk_ptr = (const uint32_t *) (digest + 4 * i);

    // For each byte in the chunk, add the step 
    for (size_t i = 0; i < sizeof(uint32_t); ++i)
      ((char *) chunk_ptr)[i] += step;

    key[i] = CHARSET[*chunk_ptr];
  }
}


// The cipher function we're trying to reverse
void SHA_CIPHER_FN(char digest[SHA_OUTPUT_LEN], const char * key)
{
  SHA256((const unsigned char *) key, strnlen(key, MAX_KEY_LENGTH), (unsigned char *) digest);
}


int main()
{
  vector <string> initial_keys = generate_keys();

  Rainbow_table <NUM_ROWS, CHAIN_LENGTH, redux_func, MAX_KEY_LENGTH, SHA_CIPHER_FN, SHA_OUTPUT_LEN> 
    rtable(initial_keys);
}
