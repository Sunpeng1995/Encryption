#include "des.h"

#define LABELBARGIN 6

uint64_t DES::cipher(const uint64_t& data, Kgen K , bool decipher) {
  if (need_info) {
    info << setw(LABELBARGIN) << left << "Input" << ": " << hex << data << endl;
  }

  uint64_t i_data = inital_premute(data);
  if (need_info) {
    info << setw(LABELBARGIN) << left << "IP" << ": " << hex << i_data << endl;
  }

  i_data = encipher_loop(i_data, K, decipher);
  uint64_t out = inital_premute(i_data, 1);
  if (need_info) {
    info << setw(LABELBARGIN) << left << "IP-1" << ": " << hex << out << endl;
    info << setw(LABELBARGIN) << left << "Output" << ": " << hex << out << endl;
  }
  return out;
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

uint64_t DES::encipher_loop(uint64_t in, Kgen K, bool decipher) {
  uint32_t l = in >> 32;
  uint32_t r = in;
  for (int i = 0; i < 16; i++) {
    uint32_t t_l = r;
    uint32_t t_r;
    if (decipher) {
      t_r = l ^ f_cal(r, K.getK(15 - i));
    }
    else {
      t_r = l ^ f_cal(r, K.getK(i));
    }
    l = t_l;
    r = t_r;

    if (need_info && i != 15) {
      uint64_t m = l;
      m <<= 32;
      m |= r;
      info << setw(LABELBARGIN) << left << dec << i << ": " << hex << m << endl;
    }
  }
  uint64_t out = 0;
  out |= r;
  out = (out << 32) | l;
  
  if (need_info) {
    info << setw(LABELBARGIN) << left << dec << 15 << ": " << hex << out << endl;
  }

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

string DES::inital_premute(string in) {
  stringstream str;
  str << hex << inital_premute(raw2bits(in));
  return str.str();
}

string DES::E_trans(string r) {
  stringstream str;
  str << hex << E_trans(raw2bits(r)).to_ullong();
  return str.str();
}

string DES::f_cal(string r, string k) {
  stringstream str;
  str << hex << f_cal(raw2bits(r), raw2bits(k));
  return str.str();
}

string DES::Xor(string l, string r) {
  stringstream str;
  str << hex << (raw2bits(l) ^ raw2bits(r));
  return str.str();
}