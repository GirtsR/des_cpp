/**
 * Created by Ģirts Rudzišs, Emīls Ozoliņš
 *
 * Some test cases:
 * --
 * plaintext: 0000000000111111111100000000001111111111000000000011111111110000
 * key: 00000000001111111111000000000011111111110000000000111111
 * ciphertext: 1110110011101001001001011100001001100001111111000011111100110011
 * --
 * --
 * plaintext: 8787878787878787 (hex)
 * key: 00001110011001100100100110011110101011011000001100111001
 * ciphertext: 0000000000000000000000000000000000000000000000000000000000000000
 * --
 */

#include <iostream>
#include <map>
#include <bitset>
#include <cctype>

std::string hex_to_bin(std::string hex) {
    std::string binary;
    for (int i = 0; i < hex.length(); i++) {
        switch (std::toupper(hex[i])) {
            case '0':binary.append("0000");
                break;
            case '1':binary.append("0001");
                break;
            case '2':binary.append("0010");
                break;
            case '3':binary.append("0011");
                break;
            case '4':binary.append("0100");
                break;
            case '5':binary.append("0101");
                break;
            case '6':binary.append("0110");
                break;
            case '7':binary.append("0111");
                break;
            case '8':binary.append("1000");
                break;
            case '9':binary.append("1001");
                break;
            case 'A':binary.append("1010");
                break;
            case 'B':binary.append("1011");
                break;
            case 'C':binary.append("1100");
                break;
            case 'D':binary.append("1101");
                break;
            case 'E':binary.append("1110");
                break;
            case 'F':binary.append("1111");
                break;
        }
    }
    return binary;
}

std::string bin_to_hex(std::string binary) {
    std::string hex;
    for (int i = 0; i < binary.length(); i += 4) {
        std::string digits = binary.substr(i, 4);
        if (digits.compare("0000") == 0) hex += '0';
        else if (digits.compare("0001") == 0) hex += '1';
        else if (digits.compare("0010") == 0) hex += '2';
        else if (digits.compare("0011") == 0) hex += '3';
        else if (digits.compare("0100") == 0) hex += '4';
        else if (digits.compare("0101") == 0) hex += '5';
        else if (digits.compare("0110") == 0) hex += '6';
        else if (digits.compare("0111") == 0) hex += '7';
        else if (digits.compare("1000") == 0) hex += '8';
        else if (digits.compare("1001") == 0) hex += '9';
        else if (digits.compare("1010") == 0) hex += 'A';
        else if (digits.compare("1011") == 0) hex += 'B';
        else if (digits.compare("1100") == 0) hex += 'C';
        else if (digits.compare("1101") == 0) hex += 'D';
        else if (digits.compare("1110") == 0) hex += 'E';
        else if (digits.compare("1111") == 0) hex += 'F';
    }
    return hex;
}

std::bitset<64> initial_permutation(const std::bitset<64> &input) {
    const int arr_size = 64;
    // IP
    int initial_permutation[arr_size] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    std::bitset<64> output;
    for (int i = 0; i < arr_size; i++) {
        output[i] = input[initial_permutation[i] - 1];
    }
    return output;
}

std::bitset<64> final_permutation(std::bitset<64> &input) {
    const int arr_size = 64;
    // IP^-1
    int final_permutation[arr_size] = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };

    std::bitset<64> output;
    for (int i = 0; i < arr_size; i++) {
        output[63 - i] = input[63 - (final_permutation[i] - 1)];
    }
    return output;
}

std::bitset<48> expansion(std::bitset<32> &input) {
    const int arr_size = 48;
    // E
    int expansion_function[arr_size] = {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    };

    std::bitset<48> output;
    for (int i = 0; i < arr_size; i++) {
        output[47 - i] = input[31 - (expansion_function[i] - 1)];
    }
    return output;
}

std::bitset<48> exclusive_or_48(std::bitset<48> &block1, std::bitset<48> &block2) {
    return block1 ^ block2;
}
std::bitset<32> exclusive_or_32(std::bitset<32> &block1, std::bitset<32> &block2) {
    return block1 ^ block2;
}

// Rotate left
std::bitset<28> rol(std::bitset<28> key, int n) {
    return (key << n) | (key >> (28 - n));
}

// Rotate right
std::bitset<28> ror(std::bitset<28> key, int n) {
    return (key >> n) | (key << (28 - n));
}

// Key rotations in rounds
int key_shift_by_round[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Key rotations in rounds while decrypting
int key_shift_by_round_decrypt[16] = {0, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Compression permutation
int com_per[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

std::bitset<56> shift_key_left(const std::bitset<56> &key, int round) {
    std::bitset<56> result;
    std::bitset<28> left;
    std::bitset<28> right;
    for (int i = 0; i < 28; i++) {
        left[i] = key[i + 28];
        right[i] = key[i];
    }
    std::bitset<28> r_left = rol(left, key_shift_by_round[round]);
    std::bitset<28> r_right = rol(right, key_shift_by_round[round]);

    for (int i = 0; i < 28; i++) {
        result[28 + i] = r_left[i];
        result[i] = r_right[i];
    }
    return result;
}

std::bitset<56> shift_key_right(const std::bitset<56> &key, int round) {
    std::bitset<56> result;
    std::bitset<28> left;
    std::bitset<28> right;
    for (int i = 0; i < 28; i++) {
        left[i] = key[i + 28];
        right[i] = key[i];
    }
    std::bitset<28> r_left = ror(left, key_shift_by_round[round]);
    std::bitset<28> r_right = ror(right, key_shift_by_round[round]);

    for (int i = 0; i < 28; i++) {
        result[28 + i] = r_left[i];
        result[i] = r_right[i];
    }
    return result;
}

std::bitset<48> compress_key(std::bitset<56> key) {
    std::bitset<48> output;
    for (int i = 0; i < 48; i++) {
        output[47 - i] = key[55 - (com_per[i] - 1)];
    }

    return output;
}

// Key permutation
int key_perm[64] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};

// Initial key permutation
std::bitset<56> init_key_perm(const std::bitset<56> &key) {
    std::bitset<56> output;
    for (int i = 0; i < key.size(); i++) {
        int id = key_perm[i] - key_perm[i] / 8 - 1; // Remove one index on every 8th bit as we don't checksum bits
        output[55 - i] = key[55 - id];
    }
    return output;
}

// S-boxes
int s_boxes[8][64] = {
    {
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    },
    {
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    },
    {
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    },
    {
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    },
    {
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    },
    {
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    },
    {
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    },
    {
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    },
};

int calc_row(std::bitset<6> bits) {
    std::bitset<2> res;
    res[0] = bits[0];
    res[1] = bits[5];
    return (int) res.to_ulong();
}

int calc_col(std::bitset<6> bits) {
    std::bitset<4> res;
    res[0] = bits[1];
    res[1] = bits[2];
    res[2] = bits[3];
    res[3] = bits[4];
    return (int) res.to_ulong();
}

std::bitset<4> s_box_value(const std::bitset<6> &value, int s_round) {
    int row = calc_row(value);
    int col = calc_col(value);

    int box_val = s_boxes[s_round][row * 16 + col];
    std::bitset<4> result((unsigned long) box_val);
    return result;
}

std::bitset<32> s_box_sub(const std::bitset<48> &value) {
    std::bitset<32> res;
    int count = 0;
    for (int i = 0; i < 8; i++) {
        unsigned long s_loc = i * 6UL;
        std::bitset<6> current_bits;
        for (int j = 0; j < 6; j++) {
            current_bits[5 - j] = value[47 - (j + s_loc)];
        }
        std::bitset<4> sbox_v = s_box_value(current_bits, i);
        for (int j = 0; j < 4; j++) {
            res[31 - count] = sbox_v[3 - j];
            count++;
        }
    }
    return res;
}

// P-Box permutation
int p_box[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};

std::bitset<32> p_box_per(std::bitset<32> &value) {
    std::bitset<32> res;

    for (int i = 0; i < 32; i++) {
        res[31 - i] = value[31 - (p_box[i] - 1)];
    }
    return res;
}

std::bitset<32> feistel(std::bitset<32> &input, std::bitset<48> &subkey) {
    std::bitset<48> in = expansion(input);
    std::bitset<48> x_out = exclusive_or_48(in, subkey);

    std::bitset<32> s_box = s_box_sub(x_out);

    std::bitset<32> p_box = p_box_per(s_box);
    return p_box;
}

std::bitset<64> encrypt_round(std::bitset<64> &in, std::bitset<56> &prev_key, int round) {
    std::cout << "Round " << round + 1 << ": ";

    std::bitset<32> left;
    std::bitset<32> right;
    for (int i = 0; i < 32; i++) {
        left[i] = in[i + 32];
        right[i] = in[i];
    }
    std::bitset<32> right_next;

    prev_key = shift_key_left(prev_key, round);
    std::bitset<48> round_key = compress_key(prev_key);

    right_next = feistel(right, round_key);

    right_next = exclusive_or_32(left, right_next);

    if (round != 15) {
        //Generate input for the next round
        for (int i = 0; i < 32; i++) {
            in[i + 32] = right[i];
            in[i] = right_next[i];
        }
    } else {
        //Last round - output swaps places
        for (int i = 0; i < 32; i++) {
            in[i + 32] = right_next[i];
            in[i] = right[i];
        }
    }
    std::cout << in.to_string() << " | " << bin_to_hex(in.to_string()) << std::endl;
    return in;
}

std::bitset<64> &decrypt_round(std::bitset<64> &in, std::bitset<56> &prev_key, int round) {
    std::cout << "Round " << round + 1 << ": ";

    std::bitset<32> left;
    std::bitset<32> right;
    for (int i = 0; i < 32; i++) {
        left[i] = in[i + 32];
        right[i] = in[i];
    }
    std::bitset<32> right_next;

    prev_key = shift_key_right(prev_key, round);
    std::bitset<48> round_key = compress_key(prev_key);

    right_next = feistel(right, round_key);

    right_next = exclusive_or_32(left, right_next);

    if (round != 15) {
        //Generate input for the next round
        for (int i = 0; i < 32; i++) {
            in[i + 32] = right[i];
            in[i] = right_next[i];
        }
    } else {
        //Last round - output swaps places
        for (int i = 0; i < 32; i++) {
            in[i + 32] = right_next[i];
            in[i] = right[i];
        }
    }
    std::cout << in.to_string() << " | " << bin_to_hex(in.to_string()) << std::endl;
    return in;
}

std::bitset<64> encrypt(const std::bitset<56> &key, std::bitset<64> &in) {
    std::bitset<56> prev_key = init_key_perm(key);
    in = initial_permutation(in);
    for (int round = 0; round < 16; round++) {
        in = encrypt_round(in, prev_key, round);
    }
    return final_permutation(in);
}
std::bitset<64>  decrypt(const std::bitset<56> &key, std::bitset<64> &in) {
    std::bitset<56> prev_key = init_key_perm(key);
    in = initial_permutation(in);
    for (int round = 0; round < 16; round++) {
        in = decrypt_round(in, prev_key, round);
    }
    return final_permutation(in);
}

int main() {
    std::string plaintext_string = "1000011110000111100001111000011110000111100001111000011110000111";
    std::string input;

//    while (true) {
//        std::cout << "Please enter a 64 bit or 16 hex digit plaintext: ";
//        std::cin >> input;
//        if (input.length() == 16) {
//            plaintext = hex_to_bin(input);
//            std::cout << "Entered hex, binary representation: " << plaintext << std::endl;
//            break;
//        } else if (input.length() == 64) {
//            plaintext = input;
//            std::string hex = bin_to_hex(plaintext);
//            std::cout << "Entered binary, hex representation: " << hex << std::endl;
//            break;
//        } else {
//            std::cout << "Incorrect plaintext length" << std::endl;
//        }
//    }

    std::string key_string = "00001110011001100100100110011110101011011000001100111001";
//    while (true) {
//        std::cout << "Please enter a 56 bit key: ";
//        std::cin >> key;
//        if (key.length() == 56) {
//            break;
//        } else {
//            std::cout << "Incorrect key length";
//        }
//    }

    //Encryption
    std::cout << "\nEncrypting..." << std::endl;

    std::bitset<64> plaintext(plaintext_string);
    std::bitset<56> key(key_string);
    std::bitset<64> in(plaintext);

    std::bitset<64> ciphertext = encrypt(key, in);

    std::cout << "\nCiphertext: " << ciphertext.to_string() << " | " << bin_to_hex(ciphertext.to_string()) << std::endl;

    //Decryption
    std::cout << "\nDecrypting..." << std::endl;

    std::bitset<64> final_plaintext = decrypt(key, ciphertext);

    std::cout << "\nDecrypted plaintext: " << final_plaintext.to_string() << " | " << bin_to_hex(final_plaintext.to_string()) << std::endl;

    if (plaintext == final_plaintext) {
        std::cout << "Plaintexts match!" << std::endl;
        return 0;
    } else {
        std::cout << "Plaintexts do not match :(" << std::endl;
        return 1;
    }
}
