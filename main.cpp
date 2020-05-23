//
//
#include<iostream>
#include<bitset>
#include<filesystem>
#include<fstream>
#include <string>       
#include <sstream> 
#include <stdlib.h>
#include <algorithm>

using namespace std;

uint8_t SBOX[16]; //SBOX ��� DES
uint8_t PBOX[8];  // PBOX ��� DES
uint8_t K[2];	 // ����� ��� DES

ifstream file_in("in.txt");			// ���� ��������� ������ �������� ����� , ����� ,
ifstream file_sbox("sbox.txt");	   // ���� �������� ��� sbox
ifstream file_pbox("pbox.txt");		// ���� �������� ��� pbox

uint8_t STATIC_TABLE[16][16];	// ������� ��������������  
uint16_t count_key[3][256];			// ������� ������
uint16_t dU[2];					// ����� ���������� �������
uint8_t dV=0;					// ���� ������ �� ��� ������� ������ ���� �������
uint8_t dX = 0;					// ��� �������� ������������� ��� ������ P 
uint8_t dY = 0;					// ��� ��� ��������� 
uint8_t max_P = 0;
uint8_t false_key[3][256];		// [2]-����� ������� , [128]-����������� ��������� ���-�� ������ ��� ��� ���� ������� 
								// 1010 �� �������� ���� �� ��������

uint8_t false_K[2];

ofstream file_diff_table("differential_table.txt");   //���� �������� ���������������� �������,
												     // ����� ��� �������� ������������ �������� ���������������� ������� 


uint8_t round_function(uint8_t r_block, uint8_t sub_key) // ������� �������,��������� 8 ������ ��� ����� ���� , ������ ����� SBOX 
{														// ������ ����� PBOX 			
	uint8_t res = 0;
	uint8_t res1 = 0;
	uint8_t res2 = 0;
	uint8_t tmp = 0;
	
	res = r_block ^ sub_key;

	res1 = SBOX[res >> 4];
	res2 = SBOX[res & 0xF];

	res = (SBOX[res >> 4] << 4) ^ SBOX[res & 0xF];

	for (int i = 0; i < 8; i++) {
		tmp ^= ((res >> (7 - PBOX[i])) & 1) << (7 - i);
	}
	res = tmp;
	return res;
}

uint16_t encrypt(uint16_t block, uint8_t* key, size_t number_of_rounds) //������� ������� ��������� ��� ������� ���������� 
{
	uint16_t cipher[20];
	uint8_t l_block = (block >> 8);
	uint8_t r_block = block & 0xFF;
	uint8_t tmp = 0;

	for (size_t i = 0; i < number_of_rounds; i++)
	{

		tmp = l_block ^ round_function(r_block, key[i]);//���

		l_block = r_block;
		r_block = tmp;
		
		cipher[i] = ((l_block << 8) | r_block);
	}

	return cipher[number_of_rounds - 1];
}

uint8_t pbox(uint8_t block)  // ������� ����������� ����� ����� SBOX ��� ����� �������� SBOX
{	
	uint8_t tmp = 0;
	uint8_t res = 0;

	res = block;

	for (int i = 0; i < 8; i++) {
		tmp ^= ((res >> (7 - PBOX[i])) & 1) << (7 - i);
	}
	res = tmp;

	return res;

}	

uint8_t sbox(uint8_t block)   // ������� ����������� ����� ����� PBOX ��� ����� �������� PBOX
{
	
	uint8_t res = 0;
	uint8_t res1 = 0;
	uint8_t res2 = 0;

	res = block;

	res1 = SBOX[res >> 4];
	res2 = SBOX[res & 0xF];

	res = (SBOX[res >> 4] << 4) ^ SBOX[res & 0xF];

	return res;
	
}

uint16_t DES(size_t number_rounds)  //���� ��������� ���������� DES;
{
	bitset<16> plaintext = 1011101100011110;
	string strg;
	bitset<8> k;


	getline(file_in, strg);					//read plaintext
	plaintext = atoi(strg.c_str());

	for (int i = 0; i < 3; i++)				// read key
	{	
		getline(file_in, strg);
		k = static_cast<bitset<8>>(strg);
		K[i] = k.to_ulong();
	}
				

	for (int j = 0; j <16; j++)		// read all SBOX		
	{
		getline(file_sbox, strg);
		SBOX[j] = atoi(strg.c_str());

	}
	

	for (int j = 0; j <8; j++) // read all PBOX
	{
		getline(file_pbox, strg);
		PBOX[j] = atoi(strg.c_str());
	}

	return encrypt(plaintext.to_ulong(), K,number_rounds);
}

uint16_t DeCipher1Round(uint16_t block, uint8_t key)
{
	uint16_t decipher;
	uint8_t l_block = (block >> 8);
	uint8_t r_block = block & 0xFF;
	uint8_t tmp = 0;


	tmp = r_block ^ round_function(l_block, key);
	
	r_block = l_block;
	l_block = tmp;
	decipher = ((l_block << 8) | r_block);

	return decipher;
}

void  DifferentialAttack()
{
	uint16_t K0[512];
	uint16_t K1[512];
	uint16_t Key[50];

	uint16_t P[2];
	uint16_t C[2][1024];
	uint16_t T, C0, C1, S;

	uint8_t X1 = 0;
	uint8_t X2 = 0;
	uint8_t Y1 = 0;
	uint8_t Y2 = 0;

	uint8_t res1 = 0;
	uint8_t res2 = 0;

	int max = 0;
	int i_max = 0;
	int count_key_2round = 0;
	int count_key_1round = 0;
	int count_key_0round = 0;
	int count = 0;

	for (size_t i = 0; i < 16; i++)			// ���������� ��� ��������� �������� ���������
	{
		for (size_t j = 0; j < 16; j++)    // � ����������� �� �������� , ������� ��� ���� X1, X2 ����� , ��� �1 ��r �2 ���� ������� �������� 
		{								  // � ����� ��������� ����� SBOX � ������� �������������� �1,�2. ��������� ��������������� ������� 		
			X1 = j;
			X2 = j ^ i;
			Y1 = SBOX[X1];
			Y2 = SBOX[X2];
			STATIC_TABLE[i][Y1^Y2] += 1;
		}
	}

	// ���������� �������������� ������� � ����
	file_diff_table << " ";
	for (int i = 0; i < 16; i++)
		file_diff_table << hex << i << " ";

	file_diff_table << endl;

	for (int i = 0; i < 16; i++)
	{
		file_diff_table << hex << i << " ";

		for (int j = 0; j < 16; j++)
			file_diff_table << to_string(static_cast<int>(STATIC_TABLE[i][j])) << " ";

		file_diff_table << endl;
	}
	// ��������� ����������

	for (int i = 0; i < 16; i++)     // ����� ���������� ����������� �� �������
	{
		for (int j = 0; j < 16; j++)
		{
			if (STATIC_TABLE[i][j]>max_P && (i, j) != (0, 0))
			{
				max_P = STATIC_TABLE[i][j];
				dX = i;
				dY = j;
				break;
			}
		}
	}

	dU[0] = dX * 4096;
	dU[1] = pbox(16 * dY);

	for (size_t j = 0; j < 32; j++)	//��� ������� P
	{
		P[0] = j;					    // ���������� ��� ������� ���������  
		P[1] = P[0] ^ dU[0];

		C[0][j] = encrypt(P[0], K, 3);	   // ������� ��� ������� ���������
		C[1][j] = encrypt(P[1], K, 3);
	}


	for (int i = 1; i < 256; i++)		//��� ������� �����
	{
		for (size_t j = 0; j < 32; j++)	//��� ������� P
		{

			C0 = pbox(sbox((C[0][j] >> 8) ^ i));
			C1 = pbox(sbox((C[1][j] >> 8) ^ i));

			T = C0 ^ C1;

			S = (dU[0] >> 8) ^ ((C[0][j] & 0xFF) ^ (C[1][j] & 0xFF));


			if (T == S /*dU[1]*/) // ������ ����� ��������� ������������ ��� ��� ���� ����� ����� ���� � ���������� � ������ ������ 
			{
				count_key[2][i] = count_key[2][i] + 1;
				// ���� �������� ������������ ������� ����� ��� ������� �� ����� 
			}						// ���������� SBOX �� ����� ����������� ������� ����� �� �������	

		}

	}

	for (int i = 0; i < 256; i++)
	{
		if (count_key[2][i] >= max)
		{
			max = count_key[2][i];
		}
	}

	cout <<"Key for Round 3 "<< endl;
	// ������� ��� ����� �������� ������� ����������� 
	for (int i = 0; i < 256; i++)
	{
		if (count_key[2][i] == max)
		{
			false_key[2][count_key_2round] = i;
			count_key_2round += 1;
			cout << bitset<8>(i) << " --- " << max << endl;
		}
	}

	cout << "Count key 3 round= " << count_key_2round << endl;

	dU[0] = ((pbox(dY * 16)<<8)|(dX*16));
	dU[1] = dX*4096;


	for (size_t j = 0; j < 32; j++)	//��� ������� P
	{
		P[0] = j;					    // ���������� ��� ������� ���������  
		P[1] = P[0] ^ dU[0];

		C[0][j] = encrypt(P[0], K, 3);	   // ������� ��� ������� ���������
		C[1][j] = encrypt(P[1], K, 3);
	}

	for (int i = 0; i < count_key_2round; i++) //�� ���� ������ 3�� ������ 
	{
		for (int j = 0; j < 256; j++)// �� ���� ��������� ������ 2-�� ������
		{
			for (int k = 0; k < 32; k++) // �� ���� ��������� �����������
			{
				C0 = pbox(sbox((DeCipher1Round(C[0][k], false_key[2][i]) >> 8) ^ j));
				C1 = pbox(sbox((DeCipher1Round(C[1][k], false_key[2][i]) >> 8) ^ j));
				T = C0 ^ C1;
				S = (dU[1] >> 8)^(DeCipher1Round(C[0][k], false_key[2][i]) & 0xFF) ^ ((DeCipher1Round(C[1][k], false_key[2][i]) & 0xFF));

				if (T == S)
				{
					count_key[1][j] += 1;
				}
			}
		}
	}

	max = 0;

	for (int i = 0; i < 256; i++)
	{
		if (count_key[1][i] >= max)
		{
			max = count_key[1][i];
		}
	}

	cout << "Key for Round 2 " << endl;

	for (int i = 0; i < 256; i++)
	{
		if (count_key[1][i] == max)
		{
			false_key[1][count_key_1round] = i;
			count_key_1round += 1;
			cout << bitset<8>(i) << " --- " << max << endl;
		}
	}
	cout << "Count key for 2 round=" <<count_key_1round << endl;

	for (int i = 0; i < count_key_2round; i++) //�� ���� ������ 3-�� ������ 
	{
		for (int j = 0; j < count_key_1round; j++) //�� ���� ������ 2�� ������ 
		{
			for (int k = 0; k < 256; k++)// �� ���� ��������� ������ 1-�� ������
			{
				P[0] = rand() % 256 + 0;
				C0 = encrypt(P[0], K, 3);
				P[1] = DeCipher1Round(DeCipher1Round(DeCipher1Round(C0, false_key[2][i]), false_key[1][j]), k);
				if (P[0] == P[1])
				{

					cout << "Calculate Key 1 round  " << bitset<8>(k) << endl;
					cout << "Calculate Key 2 round  " << bitset<8>(false_key[1][j]) << endl;
					cout << "Calculate Key 2 round  " << bitset<8>(false_key[2][i]) << endl;

					cout << "True key 1 round  " << bitset<8>(K[0]) << endl;
					cout << "True key 2 round  " << bitset<8>(K[1]) << endl;
					cout << "True key 3 round  " << bitset<8>(K[2]) << endl;
				}
			}
		}
	}

}

int main()
{
	for (int i = 0; i < 16; i++)
		for (int j = 0; j < 16; j++)
			STATIC_TABLE[i][j]=0;

	for (int i = 0; i < 256; i++)
	{
		count_key[0][i] = 0;
		count_key[1][i] = 0;
		count_key[2][i] = 0;
	}


	cout << "Encrypting......" << endl;
	cout << bitset<16>(DES(3)) << endl;
	cout << "Complete!!!!" << endl;
	cout << "Differential Attack" << endl;
	DifferentialAttack();
	cout << "Complete !!!" << endl;

	system("pause");
	return 0;
}