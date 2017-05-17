#include <iostream>
#include <bitset>

using namespace std;

class Kgen {
public:
  Kgen(uint64_t key) : m_key(key) {
    K_compute();
  }
  inline bitset<48> getK(int n) {
    return Ks[n];
  }


private:

  uint64_t m_key;
  bitset<48> Ks[16];

  const int PC1_table[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
  };

  const int PC2_table[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
  };

  const int l_shifts[16] = {
    1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
  };

  void K_compute() {
    bitset<56> key56(0);
    for (int i = 0; i < 56; i++) {
      uint8_t t = get_bit(m_key, PC1_table[i] - 1);
      key56.set(55 - i, get_bit(m_key, PC1_table[i] - 1));
    }
    bitset<28> c((key56 >> 28).to_ulong());
    bitset<28> d((key56).to_ullong());
    for (int i = 0; i < 16; i++) {
      c = (c << l_shifts[i]) | (c >> (28 - l_shifts[i]));
      d = (d << l_shifts[i]) | (d >> (28 - l_shifts[i]));
      bitset<56> t((c.to_ullong() << 28) | d.to_ullong());
      bitset<48> k;
      for (int j = 0; j < 48; j++) {
        k.set(47 - j, t[55 - (PC2_table[j] - 1)]);
      }
      Ks[i].reset();
      Ks[i] |= k;
    }
  }
  inline uint64_t get_bit(uint64_t str, int pos, int digits = 64) {
    return (str >> (digits - 1 - pos)) & 1;
  }
};