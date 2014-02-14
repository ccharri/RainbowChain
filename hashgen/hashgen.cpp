// John Norwood
// Chris Harris
// EECS 588
// hashgen.cpp

#include <iostream>
#include <string>
#include <unordered_map>
#include <cstring>
#include <openssl/sha.h>   // SHA1

using std::cout; using std::endl; using std::unordered_map;
using std::string; using std::cerr;

// Constants
const size_t HASH_OUTPUT_LEN = 20;
const size_t MAX_KEY_LEN     = 8;

const unordered_map <char, char> NIBBLE_TO_CHAR =
{
  { 0, '0' },  { 1, '1' },  { 2, '2' },  { 3, '3' },
  { 4, '4' },  { 5, '5' },  { 6, '6' },  { 7, '7' },
  { 8, '8' },  { 9, '9' },  { 10, 'a' }, { 11, 'b' }, 
  { 12, 'c' }, { 13, 'd' }, { 14, 'e' }, { 15, 'f' }
};


// Convert a binary blob to a hexadecimal string
string binary_to_hexstr(char* binary)
{
  string hexstr;
  for (size_t i = 0; i < HASH_OUTPUT_LEN; ++i)
  {
    char nibble_one = (binary[i] >> 4) & 0xf;
    char nibble_two = (binary[i] & 0xf); 

    hexstr.push_back(NIBBLE_TO_CHAR.find(nibble_one)->second);
    hexstr.push_back(NIBBLE_TO_CHAR.find(nibble_two)->second);
  }

  return hexstr;
}


int main(int argc, char** argv)
{
  if (argc != 2)
  {
    cerr << "Usage: hashgen <password>" << endl;
    return 1;
  }

  const char * pass = argv[1];
  char digest[HASH_OUTPUT_LEN];
  SHA1((const unsigned char *) pass, strnlen(pass, MAX_KEY_LEN), (unsigned char *) digest);

  cout << binary_to_hexstr(digest) << endl;
}
