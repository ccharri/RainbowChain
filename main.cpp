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
const size_t CHAIN_LENGTH   = 4000;
const string CHARACTER_SET  = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";


void best_redux_func(char key[MAX_KEY_LENGTH], const char * digest, size_t step)
{
  //cout << "REDUCING" << endl;

  for (size_t i = 0; i < MAX_KEY_LENGTH; ++i)
  {
    size_t acc = (step + digest[i]) % (CHARACTER_SET.size() + 1); 
    //cout << "Index: " << acc << endl;
    key[i] = CHARACTER_SET[acc];
  }
}


// The cipher function we're trying to reverse
void SHA_CIPHER_FN(char digest[SHA_OUTPUT_LEN], const char * key)
{
  SHA1((const unsigned char *) key, strnlen(key, MAX_KEY_LENGTH), (unsigned char *) digest);
}


int main()
{
  Rainbow_table <NUM_ROWS, CHAIN_LENGTH, best_redux_func, MAX_KEY_LENGTH, SHA_CIPHER_FN, SHA_OUTPUT_LEN> 
    rtable(CHARACTER_SET);
}
