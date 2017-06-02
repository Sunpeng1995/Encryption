/*
 * Advanced Encryption Standard
 * @author Dani Huertas
 * @email huertas.dani@gmail.com
 *
 * Based on the document FIPS PUB 197
 */
#include "aes.h"

// Multiplication in GF(2^8)
uint8_t AES::gmult(uint8_t a, uint8_t b)
{

    uint8_t p = 0, i = 0, hbs = 0;

    for (i = 0; i < 8; i++)
    {
        if (b & 1)
        {
            p ^= a;
        }

        hbs = a & 0x80;
        a <<= 1;
        if (hbs)
            a ^= 0x1b; // 0000 0001 0001 1011
        b >>= 1;
    }

    return (uint8_t)p;
}


uint8_t* AES::Rcon(uint8_t i)
{

    if (i == 1)
    {
        R[0] = 0x01; // x^(1-1) = x^0 = 1
    }
    else if (i > 1)
    {
        R[0] = 0x02;
        i--;
        while (i - 1 > 0)
        {
            R[0] = gmult(R[0], 0x02);
            i--;
        }
    }

    return R;
}

/*
 * Transformation in the Cipher and Inverse Cipher in which a Round 
 * Key is added to the State using an XOR operation. The length of a 
 * Round Key equals the size of the State (i.e., for Nb = 4, the Round 
 * Key length equals 128 bits/16 bytes).
 */
void AES::add_round_key(uint8_t *state, uint8_t *w, uint8_t r)
{

    uint8_t c;

    for (c = 0; c < Nb; c++)
    {
        state[Nb * 0 + c] = state[Nb * 0 + c] ^ w[4 * Nb * r + 4 * c + 0];
        state[Nb * 1 + c] = state[Nb * 1 + c] ^ w[4 * Nb * r + 4 * c + 1];
        state[Nb * 2 + c] = state[Nb * 2 + c] ^ w[4 * Nb * r + 4 * c + 2];
        state[Nb * 3 + c] = state[Nb * 3 + c] ^ w[4 * Nb * r + 4 * c + 3];
    }
}

/*
 * Transformation in the Cipher that takes all of the columns of the 
 * State and mixes their data (independently of one another) to 
 * produce new columns.
 */
void AES::mix_columns(uint8_t *state)
{

    uint8_t a[] = {0x02, 0x01, 0x01, 0x03}; // a(x) = {02} + {01}x + {01}x2 + {03}x3
    uint8_t i, j, col[4], res[4];

    for (j = 0; j < Nb; j++)
    {
        for (i = 0; i < 4; i++)
        {
            col[i] = state[Nb * i + j];
        }

        coef_mult(a, col, res);

        for (i = 0; i < 4; i++)
        {
            state[Nb * i + j] = res[i];
        }
    }
}

/*
 * Transformation in the Inverse Cipher that is the inverse of 
 * MixColumns().
 */
void AES::inv_mix_columns(uint8_t *state)
{

    uint8_t a[] = {0x0e, 0x09, 0x0d, 0x0b}; // a(x) = {0e} + {09}x + {0d}x2 + {0b}x3
    uint8_t i, j, col[4], res[4];

    for (j = 0; j < Nb; j++)
    {
        for (i = 0; i < 4; i++)
        {
            col[i] = state[Nb * i + j];
        }

        coef_mult(a, col, res);

        for (i = 0; i < 4; i++)
        {
            state[Nb * i + j] = res[i];
        }
    }
}

/*
 * Transformation in the Cipher that processes the State by cyclically 
 * shifting the last three rows of the State by different offsets. 
 */
void AES::shift_rows(uint8_t *state)
{

    uint8_t i, k, s, tmp;

    for (i = 1; i < 4; i++)
    {
        s = 0;
        while (s < i)
        {
            tmp = state[Nb * i + 0];

            for (k = 1; k < Nb; k++)
            {
                state[Nb * i + k - 1] = state[Nb * i + k];
            }

            state[Nb * i + Nb - 1] = tmp;
            s++;
        }
    }
}

/*
 * Transformation in the Inverse Cipher that is the inverse of 
 * ShiftRows().
 */
void AES::inv_shift_rows(uint8_t *state)
{

    uint8_t i, k, s, tmp;

    for (i = 1; i < 4; i++)
    {
        s = 0;
        while (s < i)
        {
            tmp = state[Nb * i + Nb - 1];

            for (k = Nb - 1; k > 0; k--)
            {
                state[Nb * i + k] = state[Nb * i + k - 1];
            }

            state[Nb * i + 0] = tmp;
            s++;
        }
    }
}

/*
 * Transformation in the Cipher that processes the State using a non­
 * linear byte substitution table (S-box) that operates on each of the 
 * State bytes independently. 
 */
void AES::sub_bytes(uint8_t *state)
{

    uint8_t i, j;
    uint8_t row, col;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            row = (state[Nb * i + j] & 0xf0) >> 4;
            col = state[Nb * i + j] & 0x0f;
            state[Nb * i + j] = s_box[16 * row + col];
        }
    }
}

/*
 * Transformation in the Inverse Cipher that is the inverse of 
 * SubBytes().
 */
void AES::inv_sub_bytes(uint8_t *state)
{

    uint8_t i, j;
    uint8_t row, col;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            row = (state[Nb * i + j] & 0xf0) >> 4;
            col = state[Nb * i + j] & 0x0f;
            state[Nb * i + j] = inv_s_box[16 * row + col];
        }
    }
}



/*
 * Key Expansion
 */
void AES::key_expansion(uint8_t *key, uint8_t *w)
{

    uint8_t tmp[4];
    uint8_t i, j;
    uint8_t len = Nb * (Nr + 1);

    for (i = 0; i < Nk; i++)
    {
        w[4 * i + 0] = key[4 * i + 0];
        w[4 * i + 1] = key[4 * i + 1];
        w[4 * i + 2] = key[4 * i + 2];
        w[4 * i + 3] = key[4 * i + 3];
    }

    for (i = Nk; i < len; i++)
    {
        tmp[0] = w[4 * (i - 1) + 0];
        tmp[1] = w[4 * (i - 1) + 1];
        tmp[2] = w[4 * (i - 1) + 2];
        tmp[3] = w[4 * (i - 1) + 3];

        if (i % Nk == 0)
        {

            rot_word(tmp);
            sub_word(tmp);
            coef_add(tmp, Rcon(i / Nk), tmp);
        }
        else if (Nk > 6 && i % Nk == 4)
        {

            sub_word(tmp);
        }

        w[4 * i + 0] = w[4 * (i - Nk) + 0] ^ tmp[0];
        w[4 * i + 1] = w[4 * (i - Nk) + 1] ^ tmp[1];
        w[4 * i + 2] = w[4 * (i - Nk) + 2] ^ tmp[2];
        w[4 * i + 3] = w[4 * (i - Nk) + 3] ^ tmp[3];
    }
    if (need_info) {
      for (int i = 0; i < 44; i++) {
        k_info << "w[" << dec << i << "]" << hex;
        for (int j = 0; j < 4; j++) {
          k_info << setw(2) << setfill('0') << +w[4 * i + j] << " ";
        }
        k_info << endl;
      }
    }
}

void AES::cipher(uint8_t *in, uint8_t *out, uint8_t *w)
{

    uint8_t state[4 * 4];
    uint8_t r, i, j;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            state[Nb * i + j] = in[i + 4 * j];
        }
    }

    // Save mid info
    save_info("input", 0, in);

    add_round_key(state, w, 0);
    // Save mid info
    save_info("a_key", 0, state);

    for (r = 1; r < Nr; r++)
    {
        sub_bytes(state);
        // Save mid info
        save_info("sub_B", r, state);

        shift_rows(state);
        // Save mid info
        save_info("s_row", r, state);

        mix_columns(state);
        // Save mid info
        save_info("m_col", r, state);

        add_round_key(state, w, r);
        // Save mid info
        save_info("a_key", r, state);
    }

    sub_bytes(state);
    // Save mid info
    save_info("sub_B", 10, state);

    shift_rows(state);
    // Save mid info
    save_info("s_row", 10, state);

    add_round_key(state, w, Nr);
    // Save mid info
    save_info("a_key", 10, state);

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            out[i + 4 * j] = state[Nb * i + j];
        }
    }
    // Save mid info
    save_info("output", 10, out);
}

void AES::inv_cipher(uint8_t *in, uint8_t *out, uint8_t *w)
{

    uint8_t state[4 * 4];
    uint8_t r, i, j;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            state[Nb * i + j] = in[i + 4 * j];
        }
    }

    // Save mid info
    save_info("input", 0, in);

    add_round_key(state, w, Nr);
    // Save mid info
    save_info("a_key", 0, state);

    for (r = Nr - 1; r >= 1; r--)
    {
        inv_shift_rows(state);
        // Save mid info
        save_info("s_row", Nr - r, state);

        inv_sub_bytes(state);
        // Save mid info
        save_info("sub_B", Nr - r, state);

        add_round_key(state, w, r);
        // Save mid info
        save_info("a_key", Nr - r, state);

        inv_mix_columns(state);
        // Save mid info
        save_info("m_col", Nr - r, state);
    }

    inv_shift_rows(state);
    // Save mid info
    save_info("s_row", 10, state);

    inv_sub_bytes(state);
    // Save mid info
    save_info("sub_B", 10, state);

    add_round_key(state, w, 0);
    // Save mid info
    save_info("a_key", 10, state);

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            out[i + 4 * j] = state[Nb * i + j];
        }
    }
    // Save mid info
    save_info("output", 10, out);
}

string AES::sub_bytes(string state) {
  uint8_t t[16];
  str2arr(state, t);
  sub_bytes(t);
  stringstream s;
  s << hex;
  for (int i = 0; i < 16; i++) {
    s << +(t[i] >> 4);
    s << +(t[i] & 0x0f);
  }
  return s.str();
}

string AES::mix_columns(string state) {
  uint8_t t[16];
  str2arr(state, t);
  mix_columns(t);
  stringstream s;
  s << hex;
  for (int i = 0; i < 16; i++) {
    s << +(t[i] >> 4);
    s << +(t[i] & 0x0f);
  }
  return s.str();
}

string AES::add_round_key(string state, string key, string round) {
  uint8_t t[16], w[16];
  str2arr(state, t);
  str2arr(key, w);
  int r = stoi(round);
  add_round_key(t, w, r);
  stringstream s;
  s << hex;
  for (int i = 0; i < 16; i++) {
    s << +(t[i] >> 4);
    s << +(t[i] & 0x0f);
  }
  return s.str();
}

string AES::shift_rows(string state) {
  uint8_t t[16];
  str2arr(state, t);
  shift_rows(t);
  stringstream s;
  s << hex;
  for (int i = 0; i < 16; i++) {
    s << +(t[i] >> 4);
    s << +(t[i] & 0x0f);
  }
  return s.str();
}