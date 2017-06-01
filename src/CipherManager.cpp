#include "CipherManager.h"

int CipherManager::cipherFileByDES(string filepath, string outpath, uint64_t key) {
  Kgen K(key);

  ifstream in(filepath, ios::binary);
  ofstream out(outpath, ios::binary);

  in.seekg(0, in.end);
  uint64_t length = in.tellg();
  in.seekg(0, in.beg);

  if (!in) {
    return 1;
  }

  if (!out) {
    return 2;
  }
  
  // Add origin length by uint64_t for 3 times
  for (int i = 0; i < 3; i++) {
    out.write(static_cast<char*>(static_cast<void*>(&length)), 8);
  }

  char* block;
  block = new char[8];

  for (int i = 0; i < (length / 8); i++) {
    in.read(block, 8);
    
    uint64_t data = *static_cast<uint64_t*>(static_cast<void*>(block));
    uint64_t odata;
    odata = mDes.cipher(data, K);

    out.write(static_cast<char*>(static_cast<void*>(&odata)), 8);
  }

  memset(block, 0, 8);
  int remain = length % 8;
  if (remain) {
    in.read(block, remain);
    uint64_t data = *static_cast<uint64_t*>(static_cast<void*>(block));
    uint64_t odata;
    odata = mDes.cipher(data, K);
    out.write(static_cast<char*>(static_cast<void*>(&odata)), 8);
  }

  in.close();
  out.close();

  return 0;
}

int CipherManager::decipherFileByDES(string filepath, string outpath, uint64_t key) {
  Kgen K(key);

  ifstream in(filepath, ios::binary);
  ofstream out(outpath, ios::binary);

  // Error code for ui
  if (!in) {
    return 1;
  }

  if (!out) {
    return 2;
  }

  in.seekg(0, in.end);
  uint64_t length = in.tellg();

  char* block;
  block = new char[8];

  in.seekg(0, in.beg);

  // Get and check the correction of origin length
  uint64_t len[3];
  for (int i = 0; i < 3; i++) {
    in.read(block, 8);
    len[i] = *static_cast<uint64_t*>(static_cast<void*>(block));
  }
  uint64_t real_len = 0;
  if (len[0] == len[1] && len[1] == len[2]) {
    real_len = len[0];
  }
  else if (len[0] == len[1]) {
    real_len = len[0];
  }
  else if (len[0] == len[2]) {
    real_len = len[0];
  }
  else if (len[1] == len[2]) {
    real_len = len[1];
  }
  else {
    return 3;
  }

  // Because the minimum size of decipher file is 4Bytes;
  for (int i = 0; i < (length / 8) - 4; i++) {
    in.read(block, 8);
    
    uint64_t data = *static_cast<uint64_t*>(static_cast<void*>(block));
    uint64_t odata;
    odata = mDes.cipher(data, K, 1);

    out.write(static_cast<char*>(static_cast<void*>(&odata)), 8);
  }

  in.read(block, 8);
  uint64_t data = *static_cast<uint64_t*>(static_cast<void*>(block));
  uint64_t odata;
  odata = mDes.cipher(data, K, 1);

  int remain = 8 - (length - 3*8 - real_len);
  out.write(static_cast<char*>(static_cast<void*>(&odata)), remain);

  in.close();
  out.close();

  return 0;
}

string CipherManager::cipherDigitalByDES(string digitals, uint64_t key) {
  Kgen K(key);

  saveDESKInfo(K);
  
  mDes.need_info = true;
  uint64_t data = mDes.cipher(digitals, K);
  mDes.need_info = false;

  DES_Mid_Info = mDes.get_info();

  stringstream s;
  s << hex << data;
  return s.str();
}

string CipherManager::decipherDigitalByDES(string digitals, uint64_t key) {
  Kgen K(key);

  saveDESKInfo(K);
  
  mDes.need_info = true;
  uint64_t data = mDes.cipher(digitals, K, 1);
  mDes.need_info = false;

  DES_Mid_Info = mDes.get_info();

  stringstream s;
  s << hex << data;
  return s.str();
}

void CipherManager::saveDESKInfo(Kgen k) {
  stringstream str;
  str << "K:" << endl;
  for (int i = 0; i < 16; i++) {
    str << setw(2) << right << dec << i << ": " << hex << k.getK(i).to_ullong() << endl;
  }
  this->DES_K_Info = str.str();
}

void CipherManager::saveDESMidInfo() {

}