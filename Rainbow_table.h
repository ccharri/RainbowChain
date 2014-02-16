// John Norwood
// Chris Harris
// EECS 588
// Rainbow_table.h

#ifndef RAINBOW_TABLE_H_
#define RAINBOW_TABLE_H_

#include "Base_n_number.h"
#include <thread>
#include <vector>
#include <algorithm>
#include <functional>
#include <cstring>
#include <string>
#include <iostream>
#include <fstream>
#include <chrono>

void print_key(const char * key)
{
  for (int i = 0; i < 7; ++i)
    std::cout << key[i];
}

#ifdef __CYGWIN__
#include <getopt.h>
#include <cstring>
#include <stdio.h>

#include "strnlen_cyg.h"
#endif

// Reduction and Cipher function types used by the table
typedef void (*reduction_function_t)(char * key, const char * cipher, size_t step);
typedef void (*cipher_function_t)(char * cipher, const char * key);



// The rainbow table structure
template 
<
  reduction_function_t RED_FN, // The family of reduction functions to use for this table
  size_t MAX_KEY_LEN,          // The maximum number of bytes in a key

  cipher_function_t CIPHER_FN, // The cipher function used to generate the table
  size_t CIPHER_OUTPUT_LEN     // The size of the cipher output in bytes
>
class Rainbow_table
{
public:

  // Default constructor
  Rainbow_table()
  : Rainbow_table(RAINBOW_DEFAULT_ROWS, RAINBOW_DEFAULT_CHAIN, RAINBOW_DEFAULT_CHARSET)
  {}


  // Destructor
  ~Rainbow_table()
  {
    delete [] table;
  }


  // Constructor constructs the table from the input initialization
  // key list and the list of reduction functions
  Rainbow_table(size_t num_rows_in, size_t chain_length_in, const std::string & character_set); 


  // Searches the table for the input hash, returning the corresponding
  // password if found, null otherwise
  std::string search(const char * digest);


  // Saves the table to the file with the input name
  void save(const std::string & filename) const;


// Private static constants
private:

  // Default values for the table
  static const size_t RAINBOW_DEFAULT_ROWS    = 20;
  static const size_t RAINBOW_DEFAULT_CHAIN   = 10;
  static const size_t RAINBOW_DEFAULT_THREADS = 8;
  static const size_t RAINBOW_NUM_GENERATIONS = 1;

  // The default character set used
  static const std::string RAINBOW_DEFAULT_CHARSET;


// Structure definitions
private:

  // A chain in the table, consisting of a starting and ending point
  struct Rainbow_chain
  {
    char start[MAX_KEY_LEN];
    char end  [MAX_KEY_LEN];

    bool operator <(const Rainbow_chain & other) const
    {
      return memcmp(end, other.end, MAX_KEY_LEN) < 0;
    }

    bool operator ==(const Rainbow_chain & other) const
    {
      return memcmp(end, other.end, MAX_KEY_LEN) == 0;
    }
  };


  // A list of threads for generating the table
  typedef std::vector <std::thread> thread_list_t;


// Helper functions
private:

  // Generates the table 
  void generate_table();


  // Generates a range of the table, starting at the input key and index and 
  // generating rows_per_thread rows
  void generate_table_range(size_t start_idx, size_t rows_per_thread, 
                            Base_n_number <MAX_KEY_LEN> keygen);


  // Dispatches threads to generate the table from the input row down
  void generate_table_from(Rainbow_chain * starting_row);


  // Generates an individual chain in the table starting from the input intial key, 
  // generating chainlength iterations, and writing the ending key in the input 
  // endpoint buffer
  void generate_chain_from_key(const char * initial_key, size_t chain_length, 
                               char endpoint[MAX_KEY_LEN]);


  // Generates a chain starting from the input index of the chain, with the 
  // input digest as the hash at this point, stores the ending key in the 
  // input endpoint variable
  void generate_chain_from_hash(const char * hash, size_t chain_link_index, 
                                size_t chain_length, char endpoint[MAX_KEY_LEN]);


  // Writes the next key to be generated into the slot at input table index
  void write_key(const Base_n_number <MAX_KEY_LEN> & keygen, size_t idx);


  // Dispatches a thread to generate the input number of rows from the
  // input index of the table, puts the thread in the threads list so
  // the main thread can join it.
  void dispatch_generator_thread(size_t start_idx, size_t rows_per_thread);


  // Finds the row of the table that matches the input one, returns nullptr if 
  // no such row found
  const Rainbow_chain * find_matching_endpoint(const Rainbow_chain * endpoint) const;


// Instance variables
private:

  Rainbow_chain *      table;         // The table data store
  const std::string    character_set; // The set of characters we're exploring
  size_t               next_key;      // The next key to be used for an endpoint
  const size_t         num_rows;      // Number of rows in the table
  const size_t         chain_length;  // Length of the chains, number of generations of hash 
  thread_list_t        threads;       // Generator threads
};


// The default character set used by the table
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
const std::string Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::RAINBOW_DEFAULT_CHARSET =
  "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";


// Constructor constructs the table from the input initialization
// key list and the list of reduction functions
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::Rainbow_table(
  size_t              num_rows_in,
  size_t              chain_length_in,
  const std::string & character_set_in
) 
: character_set(character_set_in), next_key(0), num_rows(num_rows_in), 
  chain_length(chain_length_in) 
{
  generate_table();
}


// Saves the table to the file with the input name
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::save(const std::string & filename) const
{
  std::ofstream rfile(filename);
  rfile << num_rows << ' ' << chain_length << std::endl;

  for(size_t i = 0; i < num_rows; ++i)
  {
    for(size_t j = 0; j < MAX_KEY_LEN; j++)
      rfile << table[i].start[j];

     rfile << ' ';

    for(size_t j = 0; j < MAX_KEY_LEN; j++)
      rfile << table[i].end[j];

     rfile << std::endl;
  }
}


// Generates the table 
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::generate_table()
{
  Rainbow_chain * start = table = new Rainbow_chain[num_rows];

  // For each provided intial key, generate a chain
  for (size_t i = 0; i < RAINBOW_NUM_GENERATIONS && size_t(start - table) < num_rows; ++i)
  {
    auto start_time = std::chrono::system_clock::now();

    generate_table_from(start);
    std::sort(table, table + num_rows);
    start = std::unique(table, table + num_rows);

    auto elapsed = std::chrono::system_clock::now() - start_time;
    std::cout << "Time: " << (std::chrono::duration_cast <std::chrono::milliseconds>(elapsed).count() / 1000.) << std::endl;
    std::cout << "There are now " << (start - table) << " unique endpoints" << std::endl;
  }

  //for (size_t i = 0; i < num_rows; ++i)
  //{
  //   print_key(table[i].start); std::cout << " -> "; print_key(table[i].end); std::cout << std::endl;
  //}
}


// Dispatches threads to generate the table from the input row down
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::generate_table_from(
  Rainbow_chain * starting_row
)
{
  size_t start_idx       = starting_row - table;
  size_t generation_rows = num_rows - start_idx;
  size_t rows_per_thread = generation_rows / RAINBOW_DEFAULT_THREADS;

  // Dispatch threads to generate the table
  for (size_t i = 0; i < RAINBOW_DEFAULT_THREADS-1; ++i, start_idx += rows_per_thread)
    dispatch_generator_thread(start_idx, rows_per_thread);

  dispatch_generator_thread(start_idx, num_rows - start_idx);

  // Join all of the threads
  std::for_each(threads.begin(), threads.end(), mem_fn(&std::thread::join));
  threads.clear();
}


// Dispatches a thread to generate the input number of rows from the
// input index of the table, puts the thread in the threads list so
// the main thread can join it.
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::dispatch_generator_thread(
  size_t start_idx,
  size_t rows_per_thread
)
{
  // Create a number where each digit represents the index of the character
  // set to use for that index of the key
  Base_n_number <MAX_KEY_LEN> keygen(character_set.length());
  keygen = next_key;
  next_key += rows_per_thread;

  // Dispatch the thread and put it in the thread list
  threads.emplace_back(&Rainbow_table::generate_table_range, this, start_idx, rows_per_thread, keygen);
}


// Generates a range of the table, starting at the input key and index and 
// generating rows_per_thread rows
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::generate_table_range(
  size_t start_idx,
  size_t rows_per_thread,
  Base_n_number <MAX_KEY_LEN> keygen
)
{
  for (size_t i = start_idx; i < start_idx + rows_per_thread; ++i)
  {
    write_key(keygen, i);
    keygen.increment();
    generate_chain_from_key(table[i].start, chain_length, table[i].end);
  }
}



// Generates a chain starting from the input index of the chain, with the input digest as the
// hash at this point, stores the ending key in the input endpoint variable
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::generate_chain_from_hash(
  const char * hash, 
  size_t       chain_link_index, 
  size_t       chain_length, 
  char         endpoint[MAX_KEY_LEN]
)
{
  // Reduce the hash to a starting key
  RED_FN(endpoint, hash, chain_link_index);
  //print_key(endpoint); std::cout << std::endl;
  
  // From this link to the end of the chain
  for (size_t i = 1; i < chain_length; ++i)
  {
    // Hash the current key, then reduce it to the next key 
    char hashbuf[CIPHER_OUTPUT_LEN];
    CIPHER_FN(hashbuf, endpoint);
    RED_FN(endpoint, hashbuf, chain_link_index + i);
    //print_key(endpoint); std::cout << std::endl;
  
  }
}
  
  

// Generates an individual chain in the table starting from the input intial key, generating
// chainlength iterations, and writing the ending key in the input endpoint buffer
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::generate_chain_from_key(
  const char * initial_key, 
  size_t       chain_length, 
  char         endpoint[MAX_KEY_LEN]
)
{
  if (chain_length == 0)
  {
    memcpy(endpoint, initial_key, MAX_KEY_LEN);
    return;
  }

  //print_key(initial_key); std::cout << std::endl;

  // Encipher the key and generate from here to end of chain from
  // first digest
  char hashbuf[CIPHER_OUTPUT_LEN];
  CIPHER_FN(hashbuf, initial_key);
  generate_chain_from_hash(hashbuf, 0, chain_length, endpoint);
}


template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
typename Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::Rainbow_chain const *
Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::find_matching_endpoint(
  const Rainbow_chain * test
) const
{
  const Rainbow_chain * itr = std::lower_bound(table, table + num_rows, *test);

  if (memcmp(itr->end, test->end, MAX_KEY_LEN) == 0)
    return itr;

  return nullptr;
}


// Searches the table for the input hash, returning the corresponding
// password if found, null otherwise
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
std::string Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::search(
  const char * digest
)
{
  // For each link in the chain try to reverse the hash as though it were there
  for (size_t i = chain_length; i > 0; --i)
  {
    Rainbow_chain test;
    generate_chain_from_hash(digest, i - 1, chain_length - i + 1, test.end);
    const Rainbow_chain * location = find_matching_endpoint(&test);

    if (location)
    {
      generate_chain_from_key(location->start, i-1, test.end);
      char real_digest[CIPHER_OUTPUT_LEN];
      CIPHER_FN(real_digest, test.end);

      if (memcmp(real_digest, digest, CIPHER_OUTPUT_LEN) == 0)
        return std::string(test.end,  MAX_KEY_LEN);
    }
  }

  return "";
}


// Writes the next key to be generated into the slot at input table index
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::write_key(
  const Base_n_number <MAX_KEY_LEN> & num,
  size_t                              index
)
{
  for (size_t i = 0; i < MAX_KEY_LEN; ++i)
    table[index].start[i] = character_set[num[i]];
}
  


#endif
