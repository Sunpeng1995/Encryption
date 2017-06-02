#pragma once
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <regex>

#include "des.h"
#include "aes.h"

using namespace std;

class CipherManager {
public:
  inline string getMidInfo() {
    return DES_Mid_Info;
  }

  inline string getKInfo() {
    return DES_K_Info;
  }

  inline string calIPByDES(string in) {
    return mDes.inital_premute(in);
  }
  inline string calEByDES(string r) {
    return mDes.E_trans(r);
  }
  inline string calFByDES(string r, string k) {
    return mDes.f_cal(r, k);
  }
  inline string calXor(string l, string r) {
    return mDes.Xor(l, r);
  }

  inline int cipherFileByDES(string filepath, string outpath, string key) {
    return cipherFileByDES(filepath, outpath, raw2bits(key));
  }
  inline int decipherFileByDES(string filepath, string outpath, string key) {
    return decipherFileByDES(filepath, outpath, raw2bits(key));
  }

  inline string cipherDigitalByDES(string digitals, string key) {
    return cipherDigitalByDES(digitals, raw2bits(key));
  }
  inline string decipherDigitalByDES(string digitals, string key) {
    return decipherDigitalByDES(digitals, raw2bits(key));
  }

  string cipherDigitalByAES(string digitals, string key) {
    return DigitalByAES(digitals, key, false);
  }
  string decipherDigitalByAES(string digitals, string key) {
    return DigitalByAES(digitals, key, true);
  }

  int cipherFileByAES(string filepath, string outpath, string key);
  int decipherFileByAES(string filepath, string outpath, string key);

  // The string size of param in must be 32 characters
  void str2arr(string in, uint8_t* arr);

  inline bool is_legal(string digitals) {
    stringstream s;
    s << "[abcdef0-9]{" << digitals.size() << "}";
    regex re(s.str());
    smatch sm;
    return regex_match(digitals, sm, re);
  }
private:
  DES mDes;
  AES mAes;
  inline uint64_t raw2bits(string raw) {
    if (raw.size() != 16) {
      // cout << "Not a 64bits string!";
      // return 0;
    }
    return strtoull(raw.c_str(), nullptr, 16);
  }
  string DES_K_Info;
  string DES_Mid_Info;

  void saveDESKInfo(Kgen k);
  void saveDESMidInfo();

  int cipherFileByDES(string filepath, string outpath, uint64_t key);
  int decipherFileByDES(string filepath, string outpath, uint64_t key);

  string cipherDigitalByDES(string digitals, uint64_t key);
  string decipherDigitalByDES(string digitals, uint64_t key);

  string DigitalByAES(string digitals, string key, bool inverse = false);
};
