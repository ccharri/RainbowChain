// John Norwood
// Chris Harris
// EECS 588
// N_number.h

#ifndef BASE_N_NUMBER_
#define BASE_N_NUMBER_

#include <cstdlib> // size_t


// A not particularly good implementation of a base n number
template <size_t NUM_PLACES>
class Base_n_number
{
public:

  // Construct the number with the input number of places
  Base_n_number(size_t base)
  : m_base(base)
  {
    for (size_t & num : m_rep)
      num = 0;
  }

  
  // Sets the number to a value
  Base_n_number & operator =(size_t val)
  {
    set_value(val);
    return *this;
  }


  // Increments the number
  void increment()
  {
    bool increment = true;

    for (size_t i = 0; i < NUM_PLACES && increment; ++i)
    {
      if (increment)
      {
        increment = (m_rep[i] == m_base - 1);
        m_rep[i]  = increment ? 0 
                              : m_rep[i] + 1;
      }
    }
  }


  // Access the idxth place in the number
  size_t operator [](size_t idx) const
  {
    return m_rep[idx];
  }


private:


  // Sets the value of the number
  void set_value(size_t val)
  {
    size_t place_val     = 1;
    size_t highest_place = 0;

    for (; highest_place < NUM_PLACES; ++highest_place, place_val *= m_base)
      if (val < place_val * m_base)
        break;

    for (; highest_place > 0 && val > 0; --highest_place)
    {
      m_rep[highest_place] = val / place_val;
      val -= m_rep[highest_place] * place_val;
      place_val /= m_base;
    }

    m_rep[0] = val;
  }
    

  size_t m_base;            // The base of the number
  size_t m_rep[NUM_PLACES]; // The representation of each "digit" of the number
};


#endif // BASE_N_NUMBER_
