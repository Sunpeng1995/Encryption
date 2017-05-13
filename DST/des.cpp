#include "des.h"

uint64_t DES::inital_premute(const uint64_t* in, bool reverse) {
  const int* table = ip_table;
  if (reverse) {
    table = rip_table;
  }
  uint64_t ret = 0;
  for (int i = 0; i < 64; i++) {
    int idx = table[i] - 1;
    uint64_t b = get_bit(*in, idx);
    set_bit(&ret, i, b);
  }
  return ret;
}

uint64_t DES::encipher_loop(uint64_t in, uint64_t k) {
  uint32_t l = in >> 32;
  uint32_t r = in;
  for (int i = 0; i < 16; i++) {
    uint32_t t_l = r;
    uint32_t t_r = l ^ f_cal(r, K[i]);
    l = t_l;
    r = t_r;
  }
  uint64_t out = 0;
  out |= r;
  out = (out << 32) | l;
  return inital_premute(&out, 1);
}

bitset<48> DES::E_trans(uint32_t r) {
  bitset<48> ret;
  for (int i = 0; i < 48; i++) {
    uint64_t a = static_cast<uint64_t>(r);
    ret.set(47 - i, get_bit(a, E_table[i] - 1, 32));
  }
  return ret;
}

uint32_t DES::f_cal(uint32_t r, bitset<48> k) {
  bitset<48> r_ex = E_trans(r);
  r_ex ^= k;
  uint32_t ret = 0;
  for (int i = 0; i < 8; i++) {
    ret |= S_table[i][get_subbits(r_ex, i)];
    if (i != 7) {
      ret = ret << 4;
    }
  }
  return P_trans(ret);
}

uint32_t DES::P_trans(uint32_t in) {
  uint64_t ret = 0;
  for (int i = 0; i < 32; i++) {
    uint32_t b = get_bit(in, P_table[i] - 1, 32);
    set_bit(&ret, i, b, 32);
  }
  return static_cast<uint32_t>(ret);
}

int main() {
  DES dst;
  uint64_t in = dst.raw2bits(string("1234567890abcdef"));
  uint64_t ip = dst.inital_premute(&in);
  dst.encipher_loop(dst.raw2bits(string("1234567890abcdef")), 12);
  bitset<48> a = dst.E_trans(dst.raw2bits(string("12345678")));
  cout << a;
  uint32_t b = dst.raw2bits(string("12345678"));
  uint32_t c = ~0;
  c = ~(c << 8);
  uint32_t d = dst.f_cal(0xabcdef12, bitset<48>(0x1234567890ab));
  return 0;
}
