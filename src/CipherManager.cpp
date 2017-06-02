#include "CipherManager.h"

int CipherManager::cipherFileByDES(string filepath, string outpath, uint64_t key) {
  Kgen K(key);

  ifstream in(filepath, ios::binary);
  ofstream out(outpath, ios::binary);

  if (!in) {
    return 1;
  }

  if (!out) {
    return 2;
  }

  in.seekg(0, in.end);
  uint64_t length = in.tellg();
  in.seekg(0, in.beg);

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

  // Because the minimum size of decipher file is 32 Bytes;
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

string CipherManager::DigitalByAES(string digitals, string key, bool inverse) {
  if (digitals.size() != 32 || key.size() != 32) {
    return string("");
  }
  uint8_t data[16], key_arr[16];
  str2arr(digitals, data);
  str2arr(key, key_arr);

  uint8_t out[16];

  // expanded key
  uint8_t w[4 * 44];

  mAes.need_info = true;

  mAes.key_expansion(key_arr, w);
  if (!inverse) {
    mAes.cipher(data, out, w);
  }
  else {
    mAes.inv_cipher(data, out, w);
  }

  mAes.need_info = false;

  AES_K_Info = mAes.get_k_info();
  AES_Mid_Info = mAes.get_mid_info();

  stringstream s;
  for (int i = 0; i < 16; i++) {
    s << hex << (out[i] >> 4);
    s << hex << (out[i] & 0x0f);
  }
  return s.str();
}

int CipherManager::cipherFileByAES(string filepath, string outpath, string key) {
  if (key.size() != 32) {
    return -1;
  }
  ifstream in(filepath, ios::binary);
  ofstream out(outpath, ios::binary);

  if (!in) {
    return 1;
  }

  if (!out) {
    return 2;
  }

  uint8_t key_arr[16], w[4 * 44];
  str2arr(key, key_arr);
  mAes.key_expansion(key_arr, w);

  in.seekg(0, in.end);
  uint64_t length = in.tellg();
  in.seekg(0, in.beg);
  uint64_t padding = 0;

  // Add origin length by 128bit for 3 times
  for (int i = 0; i < 3; i++) {
    out.write(static_cast<char*>(static_cast<void*>(&padding)), 8);
    out.write(static_cast<char*>(static_cast<void*>(&length)), 8);
  }

  char* block;
  block = new char[16];
  uint8_t out_data[16];
  for (int i = 0; i < (length / 16); i++) {
    in.read(block, 16);
    mAes.cipher(static_cast<uint8_t*>(static_cast<void*>(block)), out_data, w);
    out.write(static_cast<char*>(static_cast<void*>(out_data)), 16);
  }

  memset(block, 0, 16);
  int remain = length % 16;
  if (remain) {
    in.read(block, remain);
    mAes.cipher(static_cast<uint8_t*>(static_cast<void*>(block)), out_data, w);
    out.write(static_cast<char*>(static_cast<void*>(out_data)), 16);
  }
  
  in.close();
  out.close();
}
int CipherManager::decipherFileByAES(string filepath, string outpath, string key) {
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
  block = new char[16];

  in.seekg(0, in.beg);

  // Get and check the correction of origin length
  uint64_t len[3];
  for (int i = 0; i < 3; i++) {
    in.read(block, 16);
    len[i] = *static_cast<uint64_t*>(static_cast<void*>(block + 8));
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

  uint8_t key_arr[16], w[4 * 44];
  str2arr(key, key_arr);
  mAes.key_expansion(key_arr, w);

  // Because the minimum size of decipher file is 64 Bytes;
  uint8_t out_data[16];
  for (int i = 0; i < (length / 16) - 4; i++) {
    in.read(block, 16);
    
    mAes.inv_cipher(static_cast<uint8_t*>(static_cast<void*>(block)), out_data, w);

    out.write(static_cast<char*>(static_cast<void*>(out_data)), 16);
  }

  in.read(block, 16);
  mAes.inv_cipher(static_cast<uint8_t*>(static_cast<void*>(block)), out_data, w);

  int remain = 16 - (length - 3*16 - real_len);
  out.write(static_cast<char*>(static_cast<void*>(out_data)), remain);

  in.close();
  out.close();

  return 0;
}
