#include "des.h"
#include "aes.h"
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

  //m.cipherFileByDES("1.mkv", "1.mkv.des", "1234");
  //m.decipherFileByDES("1.mkv.des", "1_b.mkv", "1234");
  
  //m.cipherFileByDES("./2.txt", "./2.txt.des", "");
  //m.decipherFileByDES("./2.txt.des", "./2_b.txt", 0);

  //m.cipherFileByDES("3.jpg", "3.jpg.des", "12");
  //m.decipherFileByDES("3.jpg.des", "3_b.jpg", "12");

  //m.cipherFileByDES("1.png", "1.png.des", 0);
  //m.decipherFileByDES("1.png.des", "1_b.png", 0);

  m.cipherDigitalByDES("1234567890123456", "1234567890321654");
  

  string test = m.cipherDigitalByDES("1234567890abcdef", "123");
  //regex re("[abcdef0-9]{16}");
  smatch sm;
  test = "123456789012345e";
  stringstream s;
  s << "[abcdef0-9]{" << 16 << "}";
  regex re(s.str());
  bool equal = regex_match(test, sm, re);


  /* 128 bit key */
  uint8_t key2[] = {
  0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b,
  0x0c, 0x0d, 0x0e, 0x0f };

  uint8_t in[] = {
      0x00, 0x11, 0x22, 0x33,
      0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb,
      0xcc, 0xdd, 0xee, 0xff };

  uint8_t out[16]; // 128

  uint8_t *w; // expanded key

  AES aes;

  w = (uint8_t*)malloc(aes.Nb * (aes.Nr + 1) * 4);

  aes.key_expansion(key2, w);

  aes.cipher(in /* in */, out /* out */, w /* expanded key */);

  printf("out:\n");

  for (int i = 0; i < 4; i++)
  {
    printf("%x %x %x %x ", out[4 * i + 0], out[4 * i + 1], out[4 * i + 2], out[4 * i + 3]);
  }

  printf("\n");

  aes.inv_cipher(out, in, w);

  printf("msg:\n");
  for (int i = 0; i < 4; i++)
  {
    printf("%x %x %x %x ", in[4 * i + 0], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
  }

  printf("\n");

  string inaes("00112233445566778899aabbccddeeff");
  string keyaes("000102030405060708090a0b0c0d0e0f");
  string aes_res = m.cipherDigitalByAES(inaes, keyaes);
  cout << m.getMidInfoAES();
  string aes_inv = m.decipherDigitalByAES(aes_res, keyaes);
  cout << m.getMidInfoAES();
  cout << m.getKInfoAES();
  cout << inaes << endl;
  cout << aes_res << endl;
  cout << aes_inv << endl;

  cout << "calculation AES" << endl;
  cout << m.calMixColByAes("00112233445566778899aabbccddeeff") << endl;
  cout << m.calSubByAES("00112233445566778899aabbccddeeff") << endl;
  cout << m.calShiftRowByAES("00112233445566778899aabbccddeeff") << endl;
  cout << m.calAddRKeyByAes("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f", "1") << endl;

  m.cipherFileByAES("2.txt", "2.txt.aes", "000102030405060708090a0b0c0d0e0f");
  m.decipherFileByAES("2.txt.aes", "2_b.txt", "000102030405060708090a0b0c0d0e0f");

  //m.cipherFileByAES("3.jpg", "3.jpg.aes", "000102030405060708090a0b0c0d0e0f");
  //m.decipherFileByAES("3.jpg.aes", "3_b.jpg", "000102030405060708090a0b0c0d0e0f");


  system("pause");
  return 0;
}
