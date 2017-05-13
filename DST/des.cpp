#include "des.h"

uint64_t DES::cipher(const uint64_t& data, const uint64_t& key, bool decipher) {
  uint64_t i_data = inital_premute(data);
  bitset<48> k[16];
  K_compute(key, k);
  i_data = encipher_loop(i_data, k, decipher);
  return inital_premute(i_data, 1);
}

uint64_t DES::inital_premute(const uint64_t& in, bool reverse) {
  const int* table = ip_table;
  if (reverse) {
    table = rip_table;
  }
  uint64_t ret = 0;
  for (int i = 0; i < 64; i++) {
    int idx = table[i] - 1;
    uint64_t b = get_bit(in, idx);
    set_bit(&ret, i, b);
  }
  return ret;
}

uint64_t DES::encipher_loop(uint64_t in, bitset<48>* k, bool decipher) {
  uint32_t l = in >> 32;
  uint32_t r = in;
  for (int i = 0; i < 16; i++) {
    uint32_t t_l = r;
    uint32_t t_r;
    if (decipher) {
      t_r = l ^ f_cal(r, k[15 - i]);
    }
    else {
      t_r = l ^ f_cal(r, k[i]);
    }
    l = t_l;
    r = t_r;
  }
  uint64_t out = 0;
  out |= r;
  out = (out << 32) | l;
  return out;
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

void DES::K_compute(uint64_t key, bitset<48>* Ks) {
  bitset<56> key56(0);
  for (int i = 0; i < 56; i++) {
    uint8_t t = get_bit(key, PC1_table[i] - 1);
    key56.set(55 - i, get_bit(key, PC1_table[i] - 1));
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

