#include "des.h"

string DES::inital_premute(string iblock) {
  string oblock(64, '0');
  for (int i = 0; i < 64; i++) {
    oblock[i] = iblock[ip_table[i] - 1];
  }
  return oblock;
};

void DES::inital_premute(char* in, uint8_t* out) {
  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 8; j++) {
      uint8_t t = 0;
      int idx = ip_table[i * 8 + j] - 1;
      int m = idx / 8;
      int n = idx % 8;
      t = in[m] << n;
      t &= 0x80;
      t = t >> j;
      out[i] |= t;
    }
  }
}

uint64_t DES::inital_premute(const uint64_t* in) {
  uint64_t ret = 0;
  for (int i = 0; i < 64; i++) {
    int idx = ip_table[i] - 1;
    uint64_t b = get_bit(*in, idx);
    set_bit(&ret, i, b);
  }
  return ret;
}

void DES::encipher_loop(uint64_t in, uint64_t k) {
  uint32_t l = in >> 32;
  uint32_t r = in;
  for (int i = 0; i < 15; i++) {
    
  }
}

bitset<48> DES::E_trans(uint32_t r) {
  bitset<48> ret;
  for (int i = 0; i < 48; i++) {
    uint64_t a = static_cast<uint64_t>(r);
    ret.set(47 - i, get_bit(a, E_table[i] - 1, 32));
  }
  return ret;
}

int main() {
  DES dst;
  uint64_t in = dst.raw2bits(string("1234567890abcdef"));
  uint64_t ip = dst.inital_premute(&in);
  dst.encipher_loop(dst.raw2bits(string("1234567890abcdef")), 12);
  bitset<48> a = dst.E_trans(dst.raw2bits(string("12345678")));
  cout << a;
  uint32_t b = dst.raw2bits(string("12345678"));
}
