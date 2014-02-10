// John Norwood
// Chris Harris
// EECS 588
// Rainbow_table.h

#ifndef RAINBOW_TABLE_H_
#define RAINBOW_TABLE_H_

#include <vector>
#include <algorithm>
#include <functional>
#include <cstring>
#include <iostream>


// Reduction and Cipher function types used by the table
typedef void (*reduction_function_t)(char * key, const char * cipher);
typedef void (*cipher_function_t)(char * cipher, const char * key);


// Exception type
struct Rainbow_exception
{
  Rainbow_exception(const char * err_in)
  : err(err_in)
  {}

  const char * err;
};


// The rainbow table structure
template 
<
  size_t NUM_ROWS,              // The number of rows in the table
  size_t MAX_KEY_LEN,           // The maximum number of bytes in a key
  size_t CIPHER_OUTPUT_LEN,     // The size of the cipher output in bits
  cipher_function_t CIPHER_FN   // The cipher function used to generate the table
>
class Rainbow_table
{
public:

  // Constructor constructs the table from the input initialization
  // key list and the list of reduction functions
  Rainbow_table(const std::vector <reduction_function_t> & reduction_functions_in,
                const std::vector <const char *>         & intial_keys); 


// Helper functions
private:

  // Generates the table from the input initial keys
  void generate_table(const std::vector <const char *> & initial_keys);


  // Generates an individual chain in the table for index chain_number
  void generate_chain(const std::vector <const char *> & initial_keys, size_t chain_number);


// Structure definitions
private:

  // A chain in the table, consisting of a starting and ending point
  struct Rainbow_chain
  {
    char start[MAX_KEY_LEN];
    char end  [MAX_KEY_LEN];
  };


// Instance variables
private:

  // The list of reduction functions
  const std::vector <reduction_function_t> reduction_functions;

  // The table data store
  Rainbow_chain table[NUM_ROWS];
};


// Constructor constructs the table from the input initialization
// key list and the list of reduction functions
template <size_t NUM_ROWS, size_t MAX_KEY_LEN, size_t CIPHER_OUTPUT_LEN, cipher_function_t CIPHER_FN>
Rainbow_table <NUM_ROWS, MAX_KEY_LEN, CIPHER_OUTPUT_LEN, CIPHER_FN>::Rainbow_table(
  const std::vector <reduction_function_t> & reduction_functions_in,
  const std::vector <const char *>         & initial_keys
) 
: reduction_functions(reduction_functions_in)
{
  if (initial_keys.size() != NUM_ROWS)
    throw Rainbow_exception("Incorrect number of initial keys provided");
  else
    generate_table(initial_keys);
}


// Generates the table from the input initial keys
template <size_t NUM_ROWS, size_t MAX_KEY_LEN, size_t CIPHER_OUTPUT_LEN, cipher_function_t CIPHER_FN>
void Rainbow_table <NUM_ROWS, MAX_KEY_LEN, CIPHER_OUTPUT_LEN, CIPHER_FN>::generate_table(
  const std::vector <const char *> & initial_keys
)
{
  // For each provided intial key, generate a chain
  for (size_t i = 0; i < initial_keys.size(); ++i)
    generate_chain(initial_keys, i);
}


void print_key(const char * key)
{
  for (int i = 0; i < 8 && key[i]; ++i)
    std::cout << key[i];
}


// Generates an individual chain in the table for index chain_number
template <size_t NUM_ROWS, size_t MAX_KEY_LEN, size_t CIPHER_OUTPUT_LEN, cipher_function_t CIPHER_FN>
void Rainbow_table <NUM_ROWS, MAX_KEY_LEN, CIPHER_OUTPUT_LEN, CIPHER_FN>::generate_chain(
  const std::vector <const char *> & initial_keys,
  size_t                             chain_number 
)
{
  // Copy the key to the startpoint for this chain
  const char * key = initial_keys[chain_number];
  strncpy(table[chain_number].start, key, MAX_KEY_LEN);
  std::cout << "Producing chain from key ";
  print_key(key);

  // For each reduction function, encipher the key, and reduce
  // it, producing another link in the chain
  for (reduction_function_t redux_fun : reduction_functions)
  {
    // encipher the key
    char digest[CIPHER_OUTPUT_LEN];
    CIPHER_FN(digest, key);

    char keybuf[MAX_KEY_LEN];
    redux_fun(keybuf, digest);
    key = keybuf;
    std::cout << " -> ";
    print_key(key);
  }

  std::cout << std::endl;
}


#endif
