#pragma once
#include <iostream>
#include <fstream>
#include <string>

#include "des.h"

using namespace std;

class CipherManager {
public:
  void cipherFileByDES(string filepath, string outpath, uint64_t key);
  void decipherFileByDES(string filepath, string outpath, uint64_t key);
private:
  DES mDes;
};
