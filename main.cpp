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
#include <time.h>

#ifdef __CYGWIN__
#include <getopt.h>
#include <cstring>
#include <stdio.h>

#include "strnlen_cyg.h"
#endif


using std::vector; using std::string; using std::cerr;
using std::cout; using std::endl; using std::cin;
using std::istream_iterator; using std::istream;
using std::ifstream; using std::stringstream;
using std::thread; using std::mutex; using std::atomic;
using std::time_t; using std::time;


// SHA Rainbow Table params
const size_t MAX_KEY_LENGTH = 7;
const size_t SHA_OUTPUT_LEN = 20;
<<<<<<< HEAD
const size_t NUM_ROWS       = 20000000;
const size_t CHAIN_LENGTH   = 4000;
=======
>>>>>>> 7c238a70a01e4d979cbd69570c296beba929dea1
const string CHARACTER_SET  = "0123456789abcdefghijklmnopqrstuvwxyz";

atomic<long> g_num_cracked(0);
atomic<long> g_num_entries(0);
mutex g_file_lock;


// The cipher function we're trying to reverse
void SHA1_cipher_func(char digest[SHA_OUTPUT_LEN], const char * key)
{
  SHA1((const unsigned char *) key, MAX_KEY_LENGTH, (unsigned char *) digest);
}


//void SHA1_redux_func(char key[MAX_KEY_LENGTH], const char * digest, size_t step)
//{
//  uint16_t   step16     = (uint16_t) step;
//  uint16_t * digest_ptr = (uint16_t *) digest;
//
//  size_t half = MAX_KEY_LENGTH / 2;
//
//  for (size_t i = 0; i < half; ++i)
//    digest_ptr[i] ^= step16;
//
//  for (size_t i = 0; i < MAX_KEY_LENGTH ; ++i)
//  {
//    char digest_mash = digest[i] ^ digest[i + MAX_KEY_LENGTH];
//    key[i]           = CHARACTER_SET[digest_mash % (CHARACTER_SET.size())];
//  }
//}


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
const size_t DEFAULT_NUM_ROWS     = 10;
const size_t DEFAULT_CHAIN_LENGTH = 10;
const size_t MAX_FNAME            = 33;


bool parseCommands(int argc, char ** argv, char filename[MAX_FNAME],
                   size_t & num_threads, size_t & num_rows, size_t & chain_length)
{
	char c; 
  size_t chain, rows;

<<<<<<< HEAD
  while ((c = getopt (argc, argv, "f:r:c:n:")) != -1)
=======
  while ((c = getopt (argc, argv, "f:r:c:")) != -1)
>>>>>>> 7c238a70a01e4d979cbd69570c296beba929dea1
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
<<<<<<< HEAD

      case 'n':
      {
        int arg = atoi(optarg);
        if(arg <= 0)
        {
          cout << "Invalid number of threads" << endl;
          return true;
        }
        num_threads = arg;

        break;
      }

=======
>>>>>>> 7c238a70a01e4d979cbd69570c296beba929dea1
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
<<<<<<< HEAD

=======
>>>>>>> 7c238a70a01e4d979cbd69570c296beba929dea1
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

  g_file_lock.lock();
  while (hashstream >> hashstr)
  {
    g_file_lock.unlock();

    g_num_entries++;

    char hash[SHA_OUTPUT_LEN];
    hexstr_to_binary(hashstr, hash);
    string password = rtable.search(hash);

    if (password.length())
    {
      cout << "Found matching password " << password << endl;
      g_num_cracked++;
    }

    else
      cout << "Password not found" << endl;

    g_file_lock.lock();
  }
  g_file_lock.unlock();
}


// Constructs a SHA1 rainbow table, then reads in hashes in ascii format
// from the input stream and tries to crack them one by one
void crack_SHA1(istream & hashstream, size_t num_threads, size_t num_rows, size_t chain_length)
{
  // Construct the rainbow table
  SHA1_Rainbow_table_t rtable(num_rows, chain_length, CHARACTER_SET);
  rtable.save("rtable.txt");

  auto start_time = std::chrono::system_clock::now();

  vector<thread> threads;

  for(size_t i = 0; i < num_threads; ++i)
    threads.emplace_back(crack_hashes<SHA1_redux_func, MAX_KEY_LENGTH, SHA1_cipher_func, SHA_OUTPUT_LEN>, std::ref(rtable), std::ref(hashstream));

  for_each(threads.begin(), threads.end(), mem_fn(&thread::join));

  auto elapsed = std::chrono::system_clock::now() - start_time;
  cout << "Cracking Finished.  Total time = " << (std::chrono::duration_cast <std::chrono::milliseconds>(elapsed).count() / 1000.) << " seconds." << endl;
  cout << g_num_cracked << " cracked out of " << g_num_entries << " total entries." << endl;
  cout << ((double)g_num_cracked)/((double)g_num_entries)*100.d << "% cracked." << endl;
}
  

// Where it all begins
int main(int argc, char ** argv)
{
  // Read the command line args
  char filename[MAX_FNAME] = { '\0' }; 
  size_t num_threads = 1;
  size_t num_rows     = DEFAULT_NUM_ROWS; 
  size_t chain_length = DEFAULT_CHAIN_LENGTH; 

  size_t num_rows     = DEFAULT_NUM_ROWS; 
  size_t chain_length = DEFAULT_CHAIN_LENGTH; 

 	if(parseCommands(argc, argv, filename, num_rows, chain_length))
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
