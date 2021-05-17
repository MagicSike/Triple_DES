#include <iostream>
#include <string>
#include <vector>
#include <bitset>
#include <sstream>
#include <fstream>
#include "Helper.h"

std::vector<std::string> subkeys_16;
std::vector<std::string> subkeys2_16;
std::vector<std::string> subkeys3_16;

enum class TripleDES
{
	ENCRYPT, DECRYPT
};

constexpr TripleDES ENCRYPT = TripleDES::ENCRYPT;
constexpr TripleDES DECRYPT = TripleDES::DECRYPT;

inline std::bitset<28> rotateLeft(std::bitset<28> bits, unsigned int shift);

void createSubkeys(std::string t_key, unsigned int t_set);

std::string s_Function(std::string t_key6, unsigned int boxNum);

std::string f_Function(std::string t_keyR_32, std::string t_subkey);

void encrypt(std::string *t_M, unsigned int t_set);

void decrypt(std::string *t_M, unsigned int t_set);

std::string hexToASCII(std::string hex)
{
	// initialize the ASCII code string as empty.
	std::string ascii = "";
	for (size_t i = 0; i < hex.length(); i += 2)
	{
		// extract two characters from hex string
		std::string part = hex.substr(i, 2);

		if (part == "da" || part == "DA")
		{
			ascii += "\n";
		}
		else if (part == "a" || part == "A")
		{
			ascii += "\n";
		}
		else
		{
			// change it into base 16 and 
			// typecast as the character
			char ch = std::stoul(part, nullptr, 16);

			// add this char to final ASCII string
			ascii += ch;
		}

	}
	return ascii;
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		std::cout << "USAGE: TripleDES option sourceFileName" << std::endl;
		std::cout << "   option: -encrypt or -decrypt" << std::endl;
		//system("PAUSE");
		return -1;
	}

	std::string option = toLowerCase(argv[1]);
	//std::string sourceFileName = argv[2];

	TripleDES mode = ENCRYPT;

	if (option == "-decrypt")
		mode = DECRYPT;
	else if (option == "-encrypt")
		mode = ENCRYPT;
	else
	{
		std::cout << "ERROR: Invalid option." << std::endl;
		std::cout << "   Valid options: -encrypt or -decrypt" << std::endl;
		//system("PAUSE");
		return -2;
	}

	//keys
	std::string K1 = "947455E8C73BCA7D";
	std::string K2 = "3574B8E8673BCA7C";
	std::string K3 = "8374B8E8C73BC97D";

	// find the 16 key schedules with the PC1, rounds, then PC2
	createSubkeys(K1, 1);
	createSubkeys(K2, 2);
	createSubkeys(K3, 3);


	std::string fileTaken, message;
	std::stringstream messageHex;
	char character;
	std::string E;
	std::string D;

	std::ifstream inputFile; //opens a file for reading
	inputFile.open(argv[2]);

	if (!(inputFile.is_open()))
	{
		std::cerr << "File cannot be opened." << std::endl;
		//system("PAUSE");
		return -1;
	}

	while (inputFile.get(character) && !(inputFile.eof())) // gets each character until end of file
	{
			switch (mode)
			{
			case ENCRYPT:
			{
				if (character == '\n')
				{
					messageHex << 'D' << 'A';
				}
				else
					messageHex << std::hex << int(character);

				if (messageHex.str().size() >= 16)
				{
					message = messageHex.str().substr(0, 16);
					messageHex.str(messageHex.str().substr(16));

					encrypt(&message, 1);
					decrypt(&message, 2);
					encrypt(&message, 3);
					E += message;
				}
				break;
			}
			case DECRYPT:
			{
				messageHex << std::hex << character;
				if (messageHex.str().size() >= 16)
				{
					message = messageHex.str().substr(0, 16);
					messageHex.str(messageHex.str().substr(16));

					decrypt(&message, 3);
					encrypt(&message, 2);
					decrypt(&message, 1);

					D += message;
				}
				break;
			}
			default:
				break;
			}
	}

	inputFile.close();
	
	// creates a new text file if one does not exist
	std::ofstream outFile("C:\\Users\\lingi\\Desktop\\Status.txt", std::ios::trunc); // appends text to end of the file

	switch (mode)
	{
	case ENCRYPT:
	{
		message = messageHex.str();
		if (messageHex.str().size() != 16)
		{
			for (unsigned int size = message.size(); size < 16; size++)
			{
				message += "0";
			}
		}

		encrypt(&message, 1);
		decrypt(&message, 2);
		encrypt(&message, 3);
		E += message;

		//outFile << "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" << std::endl;
		outFile << E;
		//outFile << "\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" << std::endl;
		break;
	}
	case DECRYPT:
	{
		//outFile << "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" << std::endl;
		outFile << hexToASCII(D);
		//outFile << "\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" << std::endl;

		break;
	}
	}

	outFile.close();

	//std::cout << std::endl;
	//system("PAUSE");
	return 0;
}

void encrypt(std::string *t_M, unsigned int t_set)
{
	std::string keyM_64 = convertStringToBinary(*t_M);

	// initial permutation (IP)
	std::string keyIP_64;
	for (unsigned int position = 0; position < 64; position++)
	{
		keyIP_64 += keyM_64[initial_Permutation[position] - 1];
	}

	// split 64-bit to 32-bit halves
	std::string keyL_32 = keyIP_64.substr(0, keyIP_64.size() / 2);
	std::string keyR_32 = keyIP_64.substr(keyIP_64.size() / 2, keyIP_64.size());

	// feistel function
	std::string previousLeft = keyL_32;
	std::string previousRight = keyR_32;
	for (unsigned round = 0; round < 16; round++)
	{
		keyL_32 = previousRight;

		std::bitset<32> left(previousLeft);
		std::string rightS;

		if (t_set == 1)
			rightS = f_Function(previousRight, subkeys_16[round]);
		else if (t_set == 2)
			rightS = f_Function(previousRight, subkeys2_16[round]);
		else if (t_set == 3)
			rightS = f_Function(previousRight, subkeys3_16[round]);

		std::bitset<32> right(rightS);
		std::bitset<32> xOR = left ^ right;

		keyR_32 = xOR.to_string();

		previousLeft = keyL_32;
		previousRight = keyR_32;

	}

	std::string completed = keyR_32 + keyL_32;

	//final permuation
	std::string completedReverse;
	for (unsigned int position = 0; position < 64; position++)
	{
		completedReverse += completed[final_Permutation[position] - 1];
	}

	//final conversion from binary to hex
	std::string completedReverseHex;
	unsigned int start = 0;
	unsigned int end = 4;
	for (unsigned int bit_4 = 0; bit_4 < 16; bit_4++)
	{
		completedReverseHex += convertBinToHex(completedReverse.substr(start, end));
		start += 4;
	}

	*t_M = completedReverseHex;
}

void decrypt(std::string *t_M, unsigned int t_set)
{
	std::string keyM_64 = convertStringToBinary(*t_M);

	// initial permutation (IP)
	std::string keyIP_64;
	for (unsigned int position = 0; position < 64; position++)
	{
		keyIP_64 += keyM_64[initial_Permutation[position] - 1];
	}

	// split 64-bit to 32-bit halves
	std::string keyL_32 = keyIP_64.substr(0, keyIP_64.size() / 2);
	std::string keyR_32 = keyIP_64.substr(keyIP_64.size() / 2, keyIP_64.size());

	// feistel function
	std::string previousLeft = keyL_32;
	std::string previousRight = keyR_32;
	for (unsigned round = 0; round < 16; round++)
	{
		keyL_32 = previousRight;

		std::bitset<32> left(previousLeft);
		std::string rightS;

		if (t_set == 1)
			rightS = f_Function(previousRight, subkeys_16[15 - round]);
		else if (t_set == 2)
			rightS = f_Function(previousRight, subkeys2_16[15 - round]);
		else if (t_set == 3)
			rightS = f_Function(previousRight, subkeys3_16[15 - round]);

		std::bitset<32> right(rightS);
		std::bitset<32> xOR = left ^ right;

		keyR_32 = xOR.to_string();

		previousLeft = keyL_32;
		previousRight = keyR_32;

	}

	std::string completed = keyR_32 + keyL_32;

	//final permuation
	std::string completedReverse;
	for (unsigned int position = 0; position < 64; position++)
	{
		completedReverse += completed[final_Permutation[position] - 1];
	}

	//final conversion from binary to hex
	std::string completedReverseHex;
	unsigned int start = 0;
	unsigned int end = 4;
	for (unsigned int bit_4 = 0; bit_4 < 16; bit_4++)
	{
		completedReverseHex += convertBinToHex(completedReverse.substr(start, end));
		start += 4;
	}

	*t_M = completedReverseHex;
}

std::bitset<28> rotateLeft(std::bitset<28> bits, unsigned int shift)
{
	return (bits << shift) | (bits >> (28 - shift));
}

void createSubkeys(std::string t_key, unsigned int t_set)
{
	std::string key_64 = convertStringToBinary(t_key);

	// compress 64-bit to 56-bit key with PC1
	std::string key_56;
	for (unsigned int position = 0; position < 56; position++)
	{
		key_56 += key_64[PC1[position] - 1];
	}

	// split 56-bit into 28-halves
	std::string keyL_28 = key_56.substr(0, key_56.size() / 2);
	std::string keyR_28 = key_56.substr(key_56.size() / 2, key_56.size());

	std::bitset<28> bitL_28(keyL_28);
	std::bitset<28> bitR_28(keyR_28);

	// create the 16 subkeys
	for (unsigned int round = 0; round < 16; round++)
	{
		std::string subKey;
		// shifts the bits according to the rounds
		bitL_28 = rotateLeft(bitL_28, roundNum[round]);
		bitR_28 = rotateLeft(bitR_28, roundNum[round]);

		subKey = bitL_28.to_string() + bitR_28.to_string();

		// compress 56-bit to 48-bit key with PC2
		std::string subKeyPer;
		for (unsigned int position = 0; position < 48; position++)
		{
			subKeyPer += subKey[PC2[position] - 1];
		}

		if (t_set == 1)
			subkeys_16.push_back(subKeyPer); // stores the 16 subKeys for use;
		else if (t_set == 2)
			subkeys2_16.push_back(subKeyPer);
		else if (t_set == 3)
			subkeys3_16.push_back(subKeyPer);
	}

}

std::string f_Function(std::string t_keyR_32, std::string t_subkey)
{
	// expansion with E-box
	std::string key_48;
	for (unsigned position = 0; position < 48; position++)
	{
		key_48 += t_keyR_32[e_Box[position] - 1];
	}

	//XOR with subkey
	std::bitset<48> keyBits(key_48);
	std::bitset<48> subKeyBits(t_subkey);

	std::bitset<48> resultXOR = keyBits ^ subKeyBits;

	//compress 48-bit to 32-bit with s_box
	std::string resultSXOR = resultXOR.to_string();
	unsigned int start = 0;
	unsigned int end = 6;
	std::string key_32;
	for (unsigned int s = 0; s < 8; s++)
	{
		key_32 += s_Function(resultSXOR.substr(start, end), s);
		start += 6;
	}

	// p-box permutation
	std::string keyP_32;
	for (unsigned int position = 0; position < 32; position++)
	{
		keyP_32 += key_32[p_Box[position] - 1];
	}

	return keyP_32;
}


std::string s_Function(std::string t_key6, unsigned int boxNum)
{
	// first and last bit
	std::string decKey = t_key6.substr(0, 1) + t_key6.substr(t_key6.size() - 1, t_key6.size());
	// middle four bits
	std::string keyB_4 = t_key6.substr(1, t_key6.size() - 2);

	// conversion
	decKey = convertStringToDec(decKey);
	keyB_4 = convertStringToDec(keyB_4);


	// s-box 4-bits
	std::string key_4;
	switch (boxNum)
	{
	case 0:
		key_4 = convertIntToBinary(S1[std::stoi(decKey)][std::stoi(keyB_4)]);
		break;
	case 1:
		key_4 = convertIntToBinary(S2[std::stoi(decKey)][std::stoi(keyB_4)]);
		break;
	case 2:
		key_4 = convertIntToBinary(S3[std::stoi(decKey)][std::stoi(keyB_4)]);
		break;
	case 3:
		key_4 = convertIntToBinary(S4[std::stoi(decKey)][std::stoi(keyB_4)]);
		break;
	case 4:
		key_4 = convertIntToBinary(S5[std::stoi(decKey)][std::stoi(keyB_4)]);
		break;
	case 5:
		key_4 = convertIntToBinary(S6[std::stoi(decKey)][std::stoi(keyB_4)]);
		break;
	case 6:
		key_4 = convertIntToBinary(S7[std::stoi(decKey)][std::stoi(keyB_4)]);
		break;
	case 7:
		key_4 = convertIntToBinary(S8[std::stoi(decKey)][std::stoi(keyB_4)]);
		break;
	}

	return key_4;
}
