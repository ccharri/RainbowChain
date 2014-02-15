// John Norwood
// Chris Harris
// EECS 588
// main.cpp

#include "Rainbow_table.h"
#include <unistd.h>
#include <openssl/sha.h>   // SHA1
#include <openssl/md5.h>   // MD5
#include <cctype>          // isalphanum
#include <iostream>
#include <fstream>

using std::vector; using std::string; using std::cerr;
using std::cout; using std::endl; using std::cin;
using std::istream; using std::ifstream;


// SHA Rainbow Table params
const size_t MAX_KEY_LENGTH = 7;
const size_t SHA_OUTPUT_LEN = 20;
const string CHARACTER_SET  = "0123456789abcdefghijklmnopqrstuvwxyz";


// The cipher function we're trying to reverse
void SHA1_cipher_func(char digest[SHA_OUTPUT_LEN], const char * key)
{
  SHA1((const unsigned char *) key, MAX_KEY_LENGTH, (unsigned char *) digest);
}

// Reduces a SHA1 hash to a MAX_KEY_LENGTH key
void SHA1_redux_func(char key[MAX_KEY_LENGTH], const char * digest, size_t step)
{
  for (size_t i = 0; i < MAX_KEY_LENGTH; ++i)
  {
    size_t acc = (step + digest[i]) % (CHARACTER_SET.size()); 
    key[i] = CHARACTER_SET[acc];
  }
}

// The SHA1 Rainbow table type
typedef Rainbow_table <SHA1_redux_func, MAX_KEY_LENGTH, SHA1_cipher_func, SHA_OUTPUT_LEN> 
  SHA1_Rainbow_table_t;


// Other Rainbow table and various other parameters
const size_t NUM_ROWS     = 100000;
const size_t CHAIN_LENGTH = 100;
const size_t MAX_FNAME    = 33;


bool parseCommands(int argc, char ** argv, char filename[MAX_FNAME])
{
	char c; 
  while ((c = getopt (argc, argv, "f:")) != -1)
    switch (c)
    {
      case 'f':
        if (strnlen(optarg, MAX_FNAME+1) > MAX_FNAME)
        {
          cerr << "Hash file name too long" << endl;
          return true;
        }

        else
          strncpy(filename, optarg, MAX_FNAME);

        break;

      default:
     	  cerr << "Invalid arguments" << endl;
        return true;
    }

  return false;
}

int char2int(char input)
{
	if(input >= '0' && input <= '9')
		return input - '0';

	if(input >= 'A' && input <= 'F')
		return input - 'A' + 10;

	if(input >= 'a' && input <= 'f')
		return input - 'a' + 10;

  return -1;
}


void hexstr_to_binary(const string & digest, char * buffer)
{
	memset(buffer, 0, SHA_OUTPUT_LEN);
	for (size_t i = 0; i < digest.size(); i += 2)
	{
		char msn = digest[i];
		char lsn = digest[i+1];

		buffer[i/2] = (char2int(msn) << 4) + char2int(lsn);
	}
}


template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void crack_hashes(Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN> & rtable, 
                  istream & hashstream)
{
  // Read and try to crack each hash from the istream
  string hashstr;

  while (hashstream >> hashstr)
  {
    char hash[SHA_OUTPUT_LEN];
    hexstr_to_binary(hashstr, hash);
    string password = rtable.search(hash);

    if (password.length())
      cout << "Found matching password " << password << endl;
    else
      cout << "Password not found" << endl;
  }
}


// Constructs a SHA1 rainbow table, then reads in hashes in ascii format
// from the input stream and tries to crack them one by one
void crack_SHA1(istream & hashstream)
{
  // Construct the rainbow table
  SHA1_Rainbow_table_t rtable(NUM_ROWS, CHAIN_LENGTH, CHARACTER_SET);
  crack_hashes(rtable, hashstream);
}
  

// Where it all begins
int main(int argc, char ** argv)
{
  // Read the command line args
  char filename[MAX_FNAME] = { '\0' }; 
 	if(parseCommands(argc, argv, filename))
 		return 1;

  // If no filename provided, read from stdin
  if (*filename)
  {
    ifstream hashfstr(filename);
    crack_SHA1(hashfstr);
  }

  else
    crack_SHA1(cin);
}
