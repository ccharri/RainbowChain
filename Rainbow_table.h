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
#include <string>
#include <iostream>


// Reduction and Cipher function types used by the table
typedef void (*reduction_function_t)(char * key, const char * cipher, size_t step);
typedef void (*cipher_function_t)(char * cipher, const char * key);


// The rainbow table structure
template 
<
  size_t NUM_ROWS,             // The number of rows in the table
  size_t CHAIN_LENGTH,         // The number of links in each rainbow chain

  reduction_function_t RED_FN, // The family of reduction functions to use for this table
  size_t MAX_KEY_LEN,          // The maximum number of bytes in a key

  cipher_function_t CIPHER_FN, // The cipher function used to generate the table
  size_t CIPHER_OUTPUT_LEN     // The size of the cipher output in bytes
>
class Rainbow_table
{
public:

  // Constructor constructs the table from the input initialization
  // key list and the list of reduction functions
  Rainbow_table(const std::vector <std::string> & intial_keys); 


// Helper functions
private:

  // Generates the table from the input initial keys
  void generate_table(const std::vector <std::string> & initial_keys);


  // Generates an individual chain in the table starting from the input intial key, generating
  // chainlength iterations, and writing the ending key in the input endpoint buffer
  void generate_chain_from_key(const char * initial_key, size_t chain_length, char endpoint[MAX_KEY_LEN]);


  // Generates a chain starting from the input index of the chain, with the input digest as the
  // hash at this point, stores the ending key in the input endpoint variable
  void generate_chain_from_hash(const char * hash, size_t chain_link_index, char endpoint[MAX_KEY_LEN]);


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

  // The table data store
  Rainbow_chain table[NUM_ROWS];
};



// Constructor constructs the table from the input initialization
// key list and the list of reduction functions
template 
<
  size_t NUM_ROWS, size_t CHAIN_LENGTH, reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
Rainbow_table <NUM_ROWS, CHAIN_LENGTH, RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::Rainbow_table(
  const std::vector <std::string> & initial_keys
) 
{
  generate_table(initial_keys);
}


// Generates the table from the input initial keys
template 
<
  size_t NUM_ROWS, size_t CHAIN_LENGTH, reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <NUM_ROWS, CHAIN_LENGTH, RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::generate_table(
  const std::vector <std::string> & initial_keys
)
{
  // For each provided intial key, generate a chain
  for (size_t i = 0; i < NUM_ROWS; ++i)
  {
    const char * key = initial_keys[i].c_str();
    strncpy(table[i].start, key, MAX_KEY_LEN);
    generate_chain_from_key(table[i].start, CHAIN_LENGTH, table[i].end);
  }
}


// Generates a chain starting from the input index of the chain, with the input digest as the
// hash at this point, stores the ending key in the input endpoint variable
template 
<
  size_t NUM_ROWS, size_t CHAIN_LENGTH, reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <NUM_ROWS, CHAIN_LENGTH, RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::generate_chain_from_hash(
  const char * hash, 
  size_t       chain_link_index, 
  char         endpoint[MAX_KEY_LEN]
)
{
  // Reduce the hash to a starting key
  RED_FN(endpoint, hash, chain_link_index);
  
  // From this link to the end of the chain
  for (size_t i = chain_link_index; i < CHAIN_LENGTH; ++i)
  {
    // Hash the current key, then reduce it to the next key 
    char hashbuf[CIPHER_OUTPUT_LEN];
    CIPHER_FN(hashbuf, endpoint);
    RED_FN(endpoint, hashbuf, i);
  }
}
  
  

// Generates an individual chain in the table starting from the input intial key, generating
// chainlength iterations, and writing the ending key in the input endpoint buffer
template 
<
  size_t NUM_ROWS, size_t CHAIN_LENGTH, reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <NUM_ROWS, CHAIN_LENGTH, RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::generate_chain_from_key(
  const char * initial_key, 
  size_t       chain_length, 
  char         endpoint[MAX_KEY_LEN]
)
{
  // Encipher the key and generate from here to end of chain from
  // first digest
  char hashbuf[CIPHER_OUTPUT_LEN];
  CIPHER_FN(hashbuf, initial_key);
  generate_chain_from_hash(hashbuf, 0, endpoint);
}


#endif
