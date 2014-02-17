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
#include <sstream>
#include <iterator>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>

#ifdef __CYGWIN__
#include <getopt.h>
#include <cstring>
#include <stdio.h>

#include "strnlen_cyg.h"
#endif

using std::vector; using std::string; using std::cerr;
using std::cout; using std::endl; using std::cin;
using std::istream; using std::ifstream; 
using std::thread; using std::mutex; using std::atomic;


// Default Rainbow table and various other parameters
const size_t DEFAULT_NUM_ROWS      = 10;
const size_t DEFAULT_CHAIN_LENGTH  = 10;
const size_t MAX_FNAME             = 33;
const string DEFAULT_CHARACTER_SET = "0123456789abcdefghijklmnopqrstuvwxyz";


// Global counters for the number of cracked hashes
atomic<long> g_num_cracked(0);
atomic<long> g_num_entries(0);
mutex g_file_lock;



// SHA1 Rainbow Table type

// Parameters
const size_t SHA1_MAX_KEY_LENGTH = 7;
const size_t SHA1_OUTPUT_LENGTH  = 20;

// The cipher function we're trying to reverse
void SHA1_cipher_func(char digest[SHA1_OUTPUT_LENGTH], const char * key);

// The reduction function used for the SHA1 table
void SHA1_redux_func(char key[SHA1_MAX_KEY_LENGTH], const char * digest, size_t step);

// The SHA1 Rainbow table type
typedef Rainbow_table <SHA1_redux_func, SHA1_MAX_KEY_LENGTH, SHA1_cipher_func, SHA1_OUTPUT_LENGTH> 
  SHA1_Rainbow_table_t;



// Helper functions 

// Parses command line arguments and stores the supplied values
bool parseCommands(int argc, char ** argv, char filename[MAX_FNAME],
                   size_t & num_threads, size_t & num_rows, size_t & chain_length);


// Converts an input character to its hexadecimal integer value
int char2int(char input);


// Converts a hexadecimal string to a binary representation storing it in 
// the input buffer
void hexstr_to_binary(const string & digest, char * buffer);


// Runs a loop reading hashes from the input filestream and searching for the corresponding
// password in the input rainbow table
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void crack_hash_loop(Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN> & rtable, 
                     istream & hashstream);


// Dispatches threads to crack hashes read from the input filestream
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void crack_hashes(Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN> & rtable, 
                  istream & hashstream, size_t num_threads);


// Constructs a SHA1 rainbow table, then reads in hashes in ascii format
// from the input stream and tries to crack them one by one
void crack_SHA1(istream & hashstream, size_t num_threads, size_t num_rows, size_t chain_length);
  


// Where it all begins
int main(int argc, char ** argv)
{
  // Read the command line args
  char filename[MAX_FNAME] = { '\0' }; 
  size_t num_threads = 1;
  size_t num_rows     = DEFAULT_NUM_ROWS; 
  size_t chain_length = DEFAULT_CHAIN_LENGTH; 

 	if(parseCommands(argc, argv, filename, num_threads, num_rows, chain_length))
 		return 1;

  // If no filename provided, read from stdin
  if (*filename)
  {
    ifstream hashfstr(filename);
    crack_SHA1(hashfstr, num_threads, num_rows, chain_length);
  }

  else
    crack_SHA1(cin, num_threads, num_rows, chain_length);
}


// The cipher function we're trying to reverse
void SHA1_cipher_func(char digest[SHA1_OUTPUT_LENGTH], const char * key)
{
  SHA1((const unsigned char *) key, SHA1_MAX_KEY_LENGTH, (unsigned char *) digest);
}


// The reduction function used for the SHA1 table
void SHA1_redux_func(char key[SHA1_MAX_KEY_LENGTH], const char * digest, size_t step)
{
  uint16_t   step16     = (uint16_t) step;
  uint16_t * digest_ptr = (uint16_t *) digest;

  size_t half = SHA1_MAX_KEY_LENGTH / 2;

  for (size_t i = 0; i < half; ++i)
    digest_ptr[i] ^= step16;

  for (size_t i = 0; i < SHA1_MAX_KEY_LENGTH; ++i)
  {
    char digest_mash = digest[i] ^ digest[i + SHA1_MAX_KEY_LENGTH];
    key[i]           = DEFAULT_CHARACTER_SET[digest_mash % (DEFAULT_CHARACTER_SET.size())];
  }
}
//{
//  for (size_t i = 0; i < SHA1_MAX_KEY_LENGTH; ++i)
//  {
//    size_t acc = (step + digest[i]) % (DEFAULT_CHARACTER_SET.size()); 
//    key[i] = DEFAULT_CHARACTER_SET[acc];
//  }
//}

// Parses command line arguments and stores the supplied values
bool parseCommands(int argc, char ** argv, char filename[MAX_FNAME],
                   size_t & num_threads, size_t & num_rows, size_t & chain_length)
{
	char c; 
  size_t chain, rows, threads;

  while ((c = getopt (argc, argv, "f:r:c:n:")) != -1)
  {
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

      case 'n':
        threads = atoi(optarg);
        if(threads > 0)
          num_threads = threads;

        break;

      case 'c':
        chain = atoi(optarg);
        if (chain > 0)
          chain_length = chain;

        break;

      case 'r':
        rows = atoi(optarg);
        if (rows > 0)
          num_rows = rows;

        break;

      default:
     	  cerr << "Invalid arguments" << endl;
        return true;
    }
  }

  return false;
}


// Converts an input character to its hexadecimal integer value
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


// Converts a hexadecimal string to a binary representation storing it in 
// the input buffer
void hexstr_to_binary(const string & digest, char * buffer)
{
	memset(buffer, 0, SHA1_OUTPUT_LENGTH);
	for (size_t i = 0; i < digest.size(); i += 2)
	{
		char msn = digest[i];
		char lsn = digest[i+1];

		buffer[i/2] = (char2int(msn) << 4) + char2int(lsn);
	}
}

// Runs a loop reading hashes from the input filestream and searching for the corresponding
// password in the input rainbow table
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void crack_hash_loop(Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN> & rtable, 
                     istream & hashstream)
{
  // Read and try to crack each hash from the istream
  string hashstr;

  g_file_lock.lock();
  while (hashstream >> hashstr)
  {
    g_file_lock.unlock();

    g_num_entries++;

    char hash[SHA1_OUTPUT_LENGTH];
    hexstr_to_binary(hashstr, hash);
    string password = rtable.search(hash);

    if (password.length())
    {
      cout << "Found matching password " << password << endl;
      g_num_cracked++;
    }

    g_file_lock.lock();
  }

  g_file_lock.unlock();
}


// Dispatches threads to crack hashes read from the input filestream
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void crack_hashes(Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN> & rtable, 
                  istream & hashstream, size_t num_threads)
{
  auto start_time = std::chrono::system_clock::now();

  vector<thread> threads;
  for(size_t i = 0; i < num_threads; ++i)
    threads.emplace_back(crack_hash_loop<RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>, std::ref(rtable), std::ref(hashstream));

  for_each(threads.begin(), threads.end(), mem_fn(&thread::join));

  auto elapsed = std::chrono::system_clock::now() - start_time;
  cout << "Cracking Finished.  Total time = " << (std::chrono::duration_cast <std::chrono::milliseconds>(elapsed).count() / 1000.) << " seconds." << endl;
  cout << g_num_cracked << " cracked out of " << g_num_entries << " total entries." << endl;
  cout << ((double)g_num_cracked)/((double)g_num_entries)*100.d << "% cracked." << endl;
}


// Constructs a SHA1 rainbow table, then reads in hashes in ascii format
// from the input stream and tries to crack them one by one
void crack_SHA1(istream & hashstream, size_t num_threads, size_t num_rows, size_t chain_length)
{
  // Construct the rainbow table
  SHA1_Rainbow_table_t rtable(num_rows, chain_length, DEFAULT_CHARACTER_SET);
  rtable.save("rtable.txt");

  crack_hashes(rtable, hashstream, num_threads);
}
