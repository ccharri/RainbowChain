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

#include <set>
std::set <std::string> unique_keys;

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


  // Constructor constructs the table from the input initialization
  // key list and the list of reduction functions
  Rainbow_table(size_t num_rows_in, size_t chain_length_in, const std::string & character_set); 

  // Destructor
  ~Rainbow_table()
  {
    delete [] table;
    std::cout << "There are " << unique_keys.size() << " unique keys" << std::endl;
  }


  // Searches the table for the input hash, returning the corresponding
  // password if found, null otherwise
  std::string search(const char * digest);


// Structure definitions
private:

  // Default values for the table
  static const size_t RAINBOW_DEFAULT_ROWS  = 20;
  static const size_t RAINBOW_DEFAULT_CHAIN = 10;
  static const std::string RAINBOW_DEFAULT_CHARSET;


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


// Helper functions
private:

  // Finds the row of the table that matches the input one, returns nullptr if 
  // no such row found
  const Rainbow_chain * find_matching_endpoint(const Rainbow_chain * endpoint);


  // Generates the table 
  void generate_table();


  // Generates the table from the input row down
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
  void write_next_key(Rainbow_chain * starting_row);


// Instance variables
private:

  Rainbow_chain *      table;           // The table data store
  std::vector <size_t> indices;         // Indices for returning keys
  const std::string    character_set;   // The set of characters we're exploring
  const size_t         num_rows;        // Number of rows in the table
  const size_t         chain_length;    // Length of the chains, number of generations of hash 
                                        // reduction cycles
};


template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
const std::string Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::RAINBOW_DEFAULT_CHARSET =
  "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";


void print_key(const char * key)
{
  for (int i = 0; i < 8 && key[i]; ++i)
    std::cout << key[i];
}


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
: indices(MAX_KEY_LEN, 0), character_set(character_set_in),
  num_rows(num_rows_in), chain_length(chain_length_in) 
{
  generate_table();
}


// Generates the table 
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::generate_table()
{
  const static size_t NUM_GENERATIONS = 1;
  Rainbow_chain * start = table = new Rainbow_chain[num_rows];

  // For each provided intial key, generate a chain
  for (size_t i = 0; i < NUM_GENERATIONS && size_t(start - table) < num_rows; ++i)
  {
    std::cout << "Running generation " << i << std::endl;
    generate_table_from(start);
    std::sort(table, table + num_rows);
    start = std::unique(table, table + num_rows);
    std::cout << "There are now " << (start - table) << " unique endpoints" << std::endl;
  }

  for (Rainbow_chain * row = table; row < start; ++row)
  {
    std::cout << "Row " << row - table << ": "; print_key(row->start); std::cout << " -> "; print_key(row->end); std::cout << std::endl;
  }
}


// Generates the table from the input row down
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::generate_table_from(
  Rainbow_chain * starting_row
)
{
  for (Rainbow_chain * row = starting_row; row < table + num_rows; ++row)
  {
    write_next_key(row);
    generate_chain_from_key(row->start, chain_length, row->end);
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
  unique_keys.insert(std::string(endpoint, endpoint + strnlen(endpoint, MAX_KEY_LEN)));
  
  // From this link to the end of the chain
  for (size_t i = 1; i < chain_length; ++i)
  {
    // Hash the current key, then reduce it to the next key 
    char hashbuf[CIPHER_OUTPUT_LEN];
    CIPHER_FN(hashbuf, endpoint);
    RED_FN(endpoint, hashbuf, chain_link_index + i);
    unique_keys.insert(std::string(endpoint, endpoint + strnlen(endpoint, MAX_KEY_LEN)));
    std::cout << " -> ";  print_key(endpoint);
  }

  std::cout << std::endl;
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
    strncpy(endpoint, initial_key, MAX_KEY_LEN);
    return;
  }

  // Encipher the key and generate from here to end of chain from
  // first digest
  std::cout << "Generating from key "; print_key(initial_key);
  char hashbuf[CIPHER_OUTPUT_LEN];
  CIPHER_FN(hashbuf, initial_key);
  generate_chain_from_hash(hashbuf, 0, chain_length, endpoint);
}


// Writes the next key to be generated into the slot at input table index
template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
void Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::write_next_key(
  Rainbow_chain * row_ptr
)
{
  bool increment = true;

  for (size_t i = 0; i < MAX_KEY_LEN; ++i)
  {
    row_ptr->start[i] = character_set[indices[i]];

    if (increment)
    {
      increment  = (indices[i] == character_set.size() - 1);
      indices[i] = increment ? 0 
                             : indices[i] + 1;
    }
  }
}

template 
<
  reduction_function_t RED_FN, size_t MAX_KEY_LEN, 
  cipher_function_t CIPHER_FN, size_t CIPHER_OUTPUT_LEN
>
typename Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::Rainbow_chain const *
Rainbow_table <RED_FN, MAX_KEY_LEN, CIPHER_FN, CIPHER_OUTPUT_LEN>::find_matching_endpoint(
  const Rainbow_chain * test
)
{
  const Rainbow_chain * itr = std::lower_bound(table, table + num_rows, *test);

  if (strncmp(itr->end, test->end, MAX_KEY_LEN) == 0)
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
        return std::string(test.end, strnlen(test.end, MAX_KEY_LEN));
    }
  }

  return "";
}

#endif
