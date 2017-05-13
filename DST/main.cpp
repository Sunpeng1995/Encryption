#include "des.h"

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
  return 0;
}
