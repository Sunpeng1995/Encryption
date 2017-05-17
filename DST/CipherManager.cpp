#include "CipherManager.h"

void CipherManager::cipherFileByDES(string filepath, string outpath, uint64_t key) {
  Kgen K(key);

  ifstream in(filepath, ios::binary);
  ofstream out(outpath, ios::binary);

  in.seekg(0, in.end);
  uint64_t length = in.tellg();
  in.seekg(0, in.beg);


  char* block;
  block = new char[8];

  for (int i = 0; i < (length / 8); i++) {
    in.read(block, 8);
    
    //TODO: reverse order to bin
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
    out.write(static_cast<char*>(static_cast<void*>(&length)), 8);
}

void CipherManager::decipherFileByDES(string filepath, string outpath, uint64_t key) {
  Kgen K(key);

  ifstream in(filepath, ios::binary);
  ofstream out(outpath, ios::binary);

  in.seekg(0, in.end);
  uint64_t length = in.tellg();

  char* block;
  block = new char[8];


  in.seekg(0, in.beg);
  for (int i = 0; i < (length / 8) - 2; i++) {
    in.read(block, 8);
    
    //TODO: reverse order to bin
    uint64_t data = *static_cast<uint64_t*>(static_cast<void*>(block));
    uint64_t odata;
    odata = mDes.cipher(data, K, 1);

    out.write(static_cast<char*>(static_cast<void*>(&odata)), 8);
  }

  in.read(block, 8);
  uint64_t data = *static_cast<uint64_t*>(static_cast<void*>(block));
  uint64_t odata;
  odata = mDes.cipher(data, K, 1);

  in.read(block, 8);
  uint64_t real_len = *static_cast<uint64_t*>(static_cast<void*>(block));

  int remain = 8 - (length - 8 - real_len);
  out.write(static_cast<char*>(static_cast<void*>(&odata)), remain);

  out.close();
}