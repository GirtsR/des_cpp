#include <iostream>
#include <map>
#include <bitset>

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

std::string initial_permutation(std::string input) {
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

    std::string output;
    for (int i = 0; i < arr_size; i++) {
        output += input[initial_permutation[i] - 1];
    }
    return output;
}

std::string final_permutation(std::string input) {
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

    std::string output;
    for (int i = 0; i < arr_size; i++) {
        output += input[final_permutation[i] - 1];
    }
    return output;
}

std::string expansion(std::string input) {
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

    std::string output;
    for (int i = 0; i < arr_size; i++) {
        output += input[expansion_function[i] - 1];
    }
    return output;
}

std::string exclusive_or_48(std::string block1, std::string block2) {
    auto bitset = std::bitset<48>(block1) ^std::bitset<48>(block2);
    return bitset.to_string();
}
std::string exclusive_or_32(std::string block1, std::string block2) {
    auto bitset = std::bitset<32>(block1) ^std::bitset<32>(block2);
    return bitset.to_string();
}

std::string feistel(std::string input, std::string subkey) {
    //TODO - implement me
    input = expansion(input);
    std::cout << "Expanded: " << input << std::endl;
    std::string output = exclusive_or_48(input, subkey);
    std::cout << "XOR: " << output << std::endl;
    return "";
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

std::string shift_key_left(const std::string &key, int round) {
    unsigned long len = key.length();

    std::string left = key.substr(0, len / 2);
    std::string right = key.substr(len / 2);
    std::bitset<28> r_left = rol(std::bitset<28>(left), key_shift_by_round[round]);
    std::bitset<28> r_right = rol(std::bitset<28>(right), key_shift_by_round[round]);

    return r_left.to_string() + r_right.to_string();
}


std::string shift_key_right(const std::string &key, int round) {
    unsigned long len = key.length();

    std::string left = key.substr(0, len / 2);
    std::string right = key.substr(len / 2);
    std::bitset<28> r_left = ror(std::bitset<28>(left), key_shift_by_round_decrypt[round]);
    std::bitset<28> r_right = ror(std::bitset<28>(right), key_shift_by_round_decrypt[round]);

    return r_left.to_string() + r_right.to_string();
}

std::string compress_key(std::string key) {
    std::string output;
    for (int i = 0; i < 48; i++) {
        output += key[com_per[i] - 1];
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
std::string init_key_perm(std::string key) {
    std::string output;
    for (int i = 0; i < key.length(); i++) {
        int id = key_perm[i] - key_perm[i] / 8 - 1; // Remove one index on every 8th bit as we don't checksum bits
        output += key[id];
    }
    return output;
}

int main() {
    std::cout << "Welcome to this DES cipher implemntation!\n" <<
              "Created by: Ģirts Rudzišs and Emīls Ozoliņš" << std::endl;

    std::string plaintext;
    std::string input;

    while (true) {
        std::cout << "Please enter a 64 bit or 16 hex digit plaintext: ";
        std::cin >> input;
        if (input.length() == 8) {
            std::cout << "Entered hex, converting to binary" << std::endl;
            plaintext = hex_to_bin(input);
            break;
        } else if (input.length() == 64) {
            std::cout << "Entered binary" << std::endl;
            plaintext = input;
            break;
        } else {
            std::cout << "Incorrect plaintext length" << std::endl;
        }
    }

    std::string key;
    while (true) {
        std::cout << "Please enter a 56 bit key: ";
        std::cin >> key;
        if (key.length() == 56) {
            break;
        } else {
            std::cout << "Incorrect key length";
        }
    }

    //std::string in = "0000000000111111111100000000001111111111000000000011111111110000";    // 64
    //std::string key = "00000000001111111111000000000011111111110000000000111111";    // 56

    //Encryption
    std::cout << "Encrypting..." << std::endl;

    std::string in = plaintext;

    in = initial_permutation(in);

    std::string prev_key = init_key_perm(key);

    for (int round = 0; round < 16; round++) {
        std::cout << "Round " << round + 1 << ":" << std::endl;

        std::string left = in.substr(0, in.length() / 2);
        std::string right = in.substr(in.length() / 2);
        std::string right_next = right;

        prev_key = shift_key_left(prev_key, round);
        std::string round_key = compress_key(prev_key);

        right_next = feistel(right, round_key);

        right_next = exclusive_or_32(left, right_next);

        //Generate input for the next round
        in = right + right_next;
        std::cout << "Generated cipher in this round: " << in << std::endl;
    }

    std::string ciphertext = final_permutation(in);
    std::cout << "Ciphertext: " << ciphertext << " | " << bin_to_hex(ciphertext) << std::endl;

    //Decryption
    std::cout << "Decrypting..." << std::endl;

    in = initial_permutation(ciphertext);

    prev_key = init_key_perm(key);
    for (int round = 0; round < 16; round++) {
        std::cout << "Round " << round + 1 << ":" << std::endl;

        std::string left = in.substr(0, in.length() / 2);
        std::string right = in.substr(in.length() / 2);
        std::string right_next = right;

        prev_key = shift_key_right(prev_key, round);
        std::string round_key = compress_key(prev_key);

        right_next = feistel(right, round_key);

        right_next = exclusive_or_32(left, right_next);

        //Generate input for the next round
        in = right + right_next;
        std::cout << "Generated cipher in this round: " << in << std::endl;
    }

    std::string final_plaintext = final_permutation(in);
    std::cout << "Decrypted plaintext: " << final_plaintext << " | " << bin_to_hex(final_plaintext) << std::endl;

    if (plaintext == final_plaintext) {
        std::cout << "Plaintexts match!" << std::endl;
        return 0;
    } else {
        std::cout << "Plaintexts do not match :(" << std::endl;
        return 1;
    }

    // P-Box permutation
    int permutation[32] = {
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    };

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

    return 0;
}
