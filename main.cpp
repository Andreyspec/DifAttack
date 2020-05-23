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

uint8_t SBOX[16]; //SBOX для DES
uint8_t PBOX[8];  // PBOX для DES
uint8_t K[2];	 // Ключи для DES

ifstream file_in("in.txt");			// файл начальных данных открытый текст , ключи ,
ifstream file_sbox("sbox.txt");	   // файл хранящий все sbox
ifstream file_pbox("pbox.txt");		// файл хранящий все pbox

uint8_t STATIC_TABLE[16][16];	// таблица дифференциалов  
uint16_t count_key[3][256];			// счетчик ключей
uint16_t dU[2];					// равно количеству раундов
uint8_t dV=0;					// тоже массив но для данного случая один элемент
uint8_t dX = 0;					// это элементы дифференциала это дельта P 
uint8_t dY = 0;					// это соо ветсвенно 
uint8_t max_P = 0;
uint8_t false_key[3][256];		// [2]-число раундов , [128]-максимально возможное кол-во ключей так как если подошел 
								// 1010 то инверсия явно не подойдет

uint8_t false_K[2];

ofstream file_diff_table("differential_table.txt");   //файл хранящий дифференциальную таблицу,
												     // нужен для проверки правильности подсчета дифференциальной таблицы 


uint8_t round_function(uint8_t r_block, uint8_t sub_key) // функция которая,прогоняет 8 правых бит через ключ , дальше через SBOX 
{														// дальше через PBOX 			
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

uint16_t encrypt(uint16_t block, uint8_t* key, size_t number_of_rounds) //функция которая выполняет все функции шифрования 
{
	uint16_t cipher[20];
	uint8_t l_block = (block >> 8);
	uint8_t r_block = block & 0xFF;
	uint8_t tmp = 0;

	for (size_t i = 0; i < number_of_rounds; i++)
	{

		tmp = l_block ^ round_function(r_block, key[i]);//тут

		l_block = r_block;
		r_block = tmp;
		
		cipher[i] = ((l_block << 8) | r_block);
	}

	return cipher[number_of_rounds - 1];
}

uint8_t pbox(uint8_t block)  // функция прогоняющая текст через SBOX или через обратный SBOX
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

uint8_t sbox(uint8_t block)   // функция прогоняющая текст через PBOX или через обратный PBOX
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

uint16_t DES(size_t number_rounds)  //двух раундовое шифрование DES;
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

	for (size_t i = 0; i < 16; i++)			// Генерируем все возможные разности сообщений
	{
		for (size_t j = 0; j < 16; j++)    // в зависимости от разности , находим все пары X1, X2 таких , что Х1 хоr Х2 есть заданая разность 
		{								  // и сраху прогоняем через SBOX и находим соответсвующие У1,У2. Заполняем статичстическую таблицу 		
			X1 = j;
			X2 = j ^ i;
			Y1 = SBOX[X1];
			Y2 = SBOX[X2];
			STATIC_TABLE[i][Y1^Y2] += 1;
		}
	}

	// Записываем статистическую таблицу в файл
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
	// закончили записывать

	for (int i = 0; i < 16; i++)     // поиск наибольшей вероятности по таблице
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

	for (size_t j = 0; j < 32; j++)	//Для каждого P
	{
		P[0] = j;					    // Составляем два входных сообщения  
		P[1] = P[0] ^ dU[0];

		C[0][j] = encrypt(P[0], K, 3);	   // Шифруем два входных сообщения
		C[1][j] = encrypt(P[1], K, 3);
	}


	for (int i = 1; i < 256; i++)		//Для каждого ключа
	{
		for (size_t j = 0; j < 32; j++)	//Для каждого P
		{

			C0 = pbox(sbox((C[0][j] >> 8) ^ i));
			C1 = pbox(sbox((C[1][j] >> 8) ^ i));

			T = C0 ^ C1;

			S = (dU[0] >> 8) ^ ((C[0][j] & 0xFF) ^ (C[1][j] & 0xFF));


			if (T == S /*dU[1]*/) // Скорее всего сравнение неправильное так как надо брать левый блок и сравнивать с правым блоком 
			{
				count_key[2][i] = count_key[2][i] + 1;
				// если разность получившихся текстов равна той которую му нашли 
			}						// анализируя SBOX то тогда увеличиваем счетчик ключа на единицу	

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
	// Находим все ключи значение счетчик максимально 
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


	for (size_t j = 0; j < 32; j++)	//Для каждого P
	{
		P[0] = j;					    // Составляем два входных сообщения  
		P[1] = P[0] ^ dU[0];

		C[0][j] = encrypt(P[0], K, 3);	   // Шифруем два входных сообщения
		C[1][j] = encrypt(P[1], K, 3);
	}

	for (int i = 0; i < count_key_2round; i++) //по всем ключам 3го раунда 
	{
		for (int j = 0; j < 256; j++)// по всем возможным ключам 2-го раунда
		{
			for (int k = 0; k < 32; k++) // по всем возможным шифртекстам
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

	for (int i = 0; i < count_key_2round; i++) //по всем ключам 3-го раунда 
	{
		for (int j = 0; j < count_key_1round; j++) //по всем ключам 2го раунда 
		{
			for (int k = 0; k < 256; k++)// по всем возможным ключам 1-го раунда
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