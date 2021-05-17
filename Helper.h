#pragma once
#include <algorithm> 
int PC1[] = {
	57, 49, 41, 33, 25, 17,  9,
	 1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	 7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4
};

int PC2[] = {
	14, 17, 11, 24,  1,  5,
	 3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

unsigned int roundNum[] = {
	1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1
};


int initial_Permutation[] = {
	58, 50, 42, 34, 26, 18, 10,  2,
	60, 52, 44, 36, 28, 20, 12,  4,
	62, 54, 46, 38, 30, 22, 14,  6,
	64, 56, 48, 40, 32, 24, 16,  8,
	57, 49, 41, 33, 25, 17,  9,  1,
	59, 51, 43, 35, 27, 19, 11,  3,
	61, 53, 45, 37, 29, 21, 13,  5,
	63, 55, 47, 39, 31, 23, 15,  7
};

int e_Box[] = {
	32,  1,  2,  3,  4,  5,
	 4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1
};

int S1[4][16] = {
{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
{0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
{4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
{15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
};

int S2[4][16] = {
{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
{3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
{0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
{13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
};

int S3[4][16] = {
{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
{13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
{13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
{1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
};

int S4[4][16] = {
{7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
{13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
{10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
{3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
};

int S5[4][16] = {
{2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
{14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
{4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
{11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
};

int S6[4][16] = {
{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
{10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
{9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
{4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
};

int S7[4][16] = {
{4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
{13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
{1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
{6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
};

int S8[4][16] = {
{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
{1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
{7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
{2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
};

int p_Box[] = {
	16,  7, 20, 21,
	29, 12, 28, 17,
	 1, 15, 23, 26,
	 5, 18, 31, 10,
	 2,  8, 24, 14,
	32, 27,  3,  9,
	19, 13, 30,  6,
	22, 11,  4, 25
};

int  final_Permutation[] = {
	40,  8, 48, 16, 56, 24, 64, 32,
	39,  7, 47, 15, 55, 23, 63, 31,
	38,  6, 46, 14, 54, 22, 62, 30,
	37,  5, 45, 13, 53, 21, 61, 29,
	36,  4, 44, 12, 52, 20, 60, 28,
	35,  3, 43, 11, 51, 19, 59, 27,
	34,  2, 42, 10, 50, 18, 58, 26,
	33,  1, 41,  9, 49, 17, 57, 25
};

void print(std::string t_key, int t_space = 0)
{
	for (unsigned int i = 0; i < t_key.size(); i++)
	{
		std::cout << t_key[i];
		if (t_space != 0)
		{
			if ((i + 1) % t_space == 0)
				std::cout << " ";
		}
	}
}

std::string convertStringToBinary(std::string t_key)
{
	std::string binaryKey;
	for (unsigned int i = 0; i < t_key.size(); i++)
	{
		switch (t_key[i])
		{
		case '0':
			binaryKey += "0000";
			break;
		case '1':
			binaryKey += "0001";
			break;
		case '2':
			binaryKey += "0010";
			break;
		case '3':
			binaryKey += "0011";
			break;
		case '4':
			binaryKey += "0100";
			break;
		case '5':
			binaryKey += "0101";
			break;
		case '6':
			binaryKey += "0110";
			break;
		case '7':
			binaryKey += "0111";
			break;
		case '8':
			binaryKey += "1000";
			break;
		case '9':
			binaryKey += "1001";
			break;
		case 'A':
			binaryKey += "1010";
			break;
		case 'B':
			binaryKey += "1011";
			break;
		case 'C':
			binaryKey += "1100";
			break;
		case 'D':
			binaryKey += "1101";
			break;
		case 'E':
			binaryKey += "1110";
			break;
		case 'F':
			binaryKey += "1111";
			break;
		case 'a':
			binaryKey += "1010";
			break;
		case 'b':
			binaryKey += "1011";
			break;
		case 'c':
			binaryKey += "1100";
			break;
		case 'd':
			binaryKey += "1101";
			break;
		case 'e':
			binaryKey += "1110";
			break;
		case 'f':
			binaryKey += "1111";
			break;
		}
	}

	return binaryKey;
}

std::string convertBinToHex(std::string t_key)
{
	std::string hexKey = "0";
	if (t_key == "0001")
	{
		hexKey = "1";
	}
	else if (t_key == "0010")
	{
		hexKey = "2";
	}
	else if (t_key == "0011")
	{
		hexKey = "3";
	}
	else if (t_key == "0100")
	{
		hexKey = "4";
	}
	else if (t_key == "0101")
	{
		hexKey = "5";
	}
	else if (t_key == "0110")
	{
		hexKey = "6";
	}
	else if (t_key == "0111")
	{
		hexKey = "7";
	}
	else if (t_key == "1000")
	{
		hexKey = "8";
	}
	else if (t_key == "1001")
	{
		hexKey = "9";
	}
	else if (t_key == "1010")
	{
		hexKey = "A";
	}
	else if (t_key == "1011")
	{
		hexKey = "B";
	}
	else if (t_key == "1100")
	{
		hexKey = "C";
	}
	else if (t_key == "1101")
	{
		hexKey = "D";
	}
	else if (t_key == "1110")
	{
		hexKey = "E";
	}
	else if (t_key == "1111")
	{
		hexKey = "F";
	}

	return hexKey;
}

std::string convertIntToBinary(int t_key)
{
	std::string binaryKey;
	switch (t_key)
	{
	case 0:
		binaryKey += "0000";
		break;
	case 1:
		binaryKey += "0001";
		break;
	case 2:
		binaryKey += "0010";
		break;
	case 3:
		binaryKey += "0011";
		break;
	case 4:
		binaryKey += "0100";
		break;
	case 5:
		binaryKey += "0101";
		break;
	case 6:
		binaryKey += "0110";
		break;
	case 7:
		binaryKey += "0111";
		break;
	case 8:
		binaryKey += "1000";
		break;
	case 9:
		binaryKey += "1001";
		break;
	case 10:
		binaryKey += "1010";
		break;
	case 11:
		binaryKey += "1011";
		break;
	case 12:
		binaryKey += "1100";
		break;
	case 13:
		binaryKey += "1101";
		break;
	case 14:
		binaryKey += "1110";
		break;
	case 15:
		binaryKey += "1111";
		break;
	}
	return binaryKey;
}

std::string convertStringToDec(std::string t_key)
{
	std::string decKey = "0";
	
	if (t_key == "01" || t_key == "0001")
	{
		decKey = "1";
	}
	else if (t_key == "10" || t_key == "0010")
	{
		decKey = "2";
	}
	else if (t_key == "11" || t_key == "0011")
	{
		decKey = "3";
	}
	else if (t_key == "0100")
	{
		decKey = "4";
	}
	else if (t_key == "0101")
	{
		decKey = "5";
	}
	else if (t_key == "0110")
	{
		decKey = "6";
	}
	else if (t_key == "0111")
	{
		decKey = "7";
	}
	else if (t_key == "1000")
	{
		decKey = "8";
	}
	else if (t_key == "1001")
	{
		decKey = "9";
	}
	else if (t_key == "1010")
	{
		decKey = "10";
	}
	else if (t_key == "1011")
	{
		decKey = "11";
	}
	else if (t_key == "1100")
	{
		decKey = "12";
	}
	else if (t_key == "1101")
	{
		decKey = "13";
	}
	else if (t_key == "1110")
	{
		decKey = "14";
	}
	else if (t_key == "1111")
	{
		decKey = "15";
	}
	
	return decKey;
}
 
inline std::string toLowerCase(const std::string str)
{
	std::string lowerCase(str);
	std::transform(lowerCase.begin(), lowerCase.end(), lowerCase.begin(), ::tolower);
	return lowerCase;
}

