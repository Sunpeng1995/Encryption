#include "des.h"
#include "CipherManager.h"
#include <regex>

int main() {
  DES dst;
  uint64_t input = 0b0110110001100101011000010111001001101110011010010110111001100111;
  uint64_t key = 0b0110001101101111011011010111000001110101011101000110010101110010;
  uint64_t output = 0b1000100101001100101101110011001011011111100111011110000100000011;
  uint64_t encipher = dst.cipher(input, key);
  uint64_t decipher = dst.cipher(encipher, key, true);
  if (encipher == output && input == decipher) {
    cout << "success!" << endl;
  }
  else {
    cout << "fuck!" << endl;
  }

  CipherManager m;
  
  m.cipherFileByDES("2.txt", "2.txt.des", "");
  m.decipherFileByDES("2.txt.des", "2_b.txt", 0);

  m.cipherFileByDES("1.png", "1.png.des", 0);
  m.decipherFileByDES("1.png.des", "1_b.png", 0);

  m.cipherDigitalByDES("1234567890123456", "1234567890321654");
  

  string test = m.cipherDigitalByDES("1234567890abcdef", "123");
  //regex re("[abcdef0-9]{16}");
  smatch sm;
  test = "123456789012345e";
  stringstream s;
  s << "[abcdef0-9]{" << 16 << "}";
  regex re(s.str());
  bool equal = regex_match(test, sm, re);
  return 0;
}
