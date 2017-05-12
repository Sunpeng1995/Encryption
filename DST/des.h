#pragma once
#include <string>
#include <iostream>
#include <bitset>

using namespace std;

class DES {
public:

//private:

  const int ip_table[64] = {
      58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7
  };

  const int E_table[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
  };

  string inital_premute(string iblock);
  void inital_premute(char* in, uint8_t* out);
  uint64_t inital_premute(const uint64_t* in);
  void encipher_loop(uint64_t in, uint64_t k);
  bitset<48> E_trans(uint32_t r);
  
  inline uint64_t raw2bits(string raw) {
    if (raw.size() != 16) {
      // cout << "Not a 64bits string!";
      // return 0;
    }
    return strtoull(raw.c_str(), nullptr, 16);
  }

  inline uint64_t get_bit(uint64_t str, int pos, int digits = 64) {
    return (str >> (digits - 1 - pos)) & 1;
  }

  inline void set_bit(uint64_t* str, int pos, uint64_t bit, int digits = 64) {
    *str |= (bit << (digits - 1 - pos));
  }

};