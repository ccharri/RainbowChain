// John Norwood
// Chris Harris
// EECS 588
// main.cpp

#include "Rainbow_table.h"
#include <openssl/sha.h>   // SHA256
#include <cctype>          // isalphanum

using std::vector;

const size_t MAX_KEY_LENGTH = 8;
const size_t SHA_OUTPUT_LEN = 32;
const size_t NUM_ROWS       = 3;
const size_t CHAIN_LENGTH   = 100;


void reduceone(char key[MAX_KEY_LENGTH], const char * digest, size_t step)
{
  size_t ctr = 0;
  for (size_t i = 0; i < SHA_OUTPUT_LEN && ctr < MAX_KEY_LENGTH; ++i)
  {
    if (isalnum(digest[i]))
      key[ctr++] = digest[i];
  }

  if (ctr < MAX_KEY_LENGTH)
    key[ctr] = '\0';
}


void SHA_CIPHER_FN(char digest[SHA_OUTPUT_LEN], const char * key)
{
  SHA256((const unsigned char *) key, strnlen(key, MAX_KEY_LENGTH), (unsigned char *) digest);
}


int main()
{
  vector <const char *>         initial_keys        = { "swordfi", "another", "iloveyou" };

  Rainbow_table <NUM_ROWS, CHAIN_LENGTH, reduceone, MAX_KEY_LENGTH, SHA_CIPHER_FN, SHA_OUTPUT_LEN> 
    rtable(initial_keys);
}
