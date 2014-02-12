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
  Rainbow_table(const std::string & character_set); 


// Helper functions
private:

  // Generates the table from the input initial keys
  void generate_table();


  // Generates an individual chain in the table starting from the input intial key, generating
  // chainlength iterations, and writing the ending key in the input endpoint buffer
  void generate_chain_from_key(const char * initial_key, size_t chain_length, char endpoint[MAX_KEY_LEN]);


  // Generates a chain starting from the input index of the chain, with the input digest as the
  // hash at this point, stores the ending key in the input endpoint variable
  void generate_chain_from_hash(const char * hash, size_t chain_link_index, char endpoint[MAX_KEY_LEN]);


  // Writes the next key to be generated into the slot at input table index
  void write_next_key(size_t table_index);


// Structure definitions
private:

  // A chain in the table, consisting of a starting and ending point
  struct Rainbow_chain
  {
    char start[MAX_KEY_LEN];
    char end  [MAX_KEY_LEN];

    bool operator <(const Rainbow_chain & other) const
    {
      return strncmp(end, other.end, MAX_KEY_LEN) < 0;
    }

    bool operator ==(const Rainbow_chain & other) const
    {
      return strncmp(end, other.end, MAX_KEY_LEN) == 0;
    }
  };


// Instance variables
private:

  Rainbow_chain        table[NUM_ROWS]; // The table data store
  std::vector <size_t> indices;         // Indices for returning keys
  const std::string    character_set;   // The set of characters we're exploring
};



void print_key(const char * key)
{
  for (int i = 0; i < 8; ++i)
    std::cout << key[i];
}


// Constructor constructs the table from the input initialization
// key list and the list of reduction functions
template 
<
  size_t NUM_ROWS, size_t CHAIN_LENGTH, reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
Rainbow_table <NUM_ROWS, CHAIN_LENGTH, RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::Rainbow_table(
  const std::string & character_set_in
) 
: indices(MAX_KEY_LEN, 0), character_set(character_set_in)
{
  generate_table();

  for (size_t i = 0; i < NUM_ROWS; ++i)
  {
    std::cout << "Row " << i << ": "; print_key(table[i].start); std::cout << " -> "; print_key(table[i].end); std::cout << std::endl;
  }

  std::cout << "There are " << std::unique(table, table + NUM_ROWS) - table << " unique endpoints" << std::endl;
}


// Generates the table from the input initial keys
template 
<
  size_t NUM_ROWS, size_t CHAIN_LENGTH, reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <NUM_ROWS, CHAIN_LENGTH, RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::generate_table()
{
  // For each provided intial key, generate a chain
  for (size_t i = 0; i < NUM_ROWS; ++i)
  {
    write_next_key(i);
    generate_chain_from_key(table[i].start, CHAIN_LENGTH, table[i].end);
  }

  std::sort(table, table + NUM_ROWS);
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


// Writes the next key to be generated into the slot at input table index
template 
<
  size_t NUM_ROWS, size_t CHAIN_LENGTH, reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <NUM_ROWS, CHAIN_LENGTH, RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::write_next_key(size_t table_index)
{
  bool increment = true;

  for (size_t i = 0; i < MAX_KEY_LEN; ++i)
  {
    table[table_index].start[i] = character_set[indices[i]];

    if (increment)
    {
      increment  = (indices[i] == character_set.size() - 1);
      indices[i] = increment ? 0 
                             : indices[i] + 1;
    }
  }
}


#endif
