#pragma once

#include <list>
#include <vector>
#include <string>

using namespace std;

class Crypto {
	typedef vector<bool> Data;

	Data padding(const Data &block);
	Data encryptBlock(const Data &block);
	Data decryptBlock(const Data &block);
	list<Data> slice(const Data &data);
	Data accumulate(const list<Data> &li);
	Data initPermute(const Data &block);
	Data initPermuteInverse(const Data &block);
	Data subKeyIteration(const Data &block, const bool reverse = false);
	Data FeistelRound(const Data &block, const Data &subKey);
	Data permute(const Data &block, const vector<int> &table);
	Data bitwiseOr(const Data &a, const Data &b);
	Data bitwiseXor(const Data &a, const Data &b);
	Data eExpand(const Data &block);
	vector<Data> intoSix(const Data &block);
	Data sixToFour(Data bits, int slot);
	Data& appendData(Data &dest, const Data &append);
	Data pPermute(const Data &str);
	list<Data> genSubKey();
	Data makeSubstring(const Data &data, int pos, int len);
	Data& circularShiftLeft(Data &data, int times = 1);
	Data stringToBinary(const string &str);
	string binaryToString(const Data &data);

	Data key;
public:
	Crypto(const Data &key);
	Data encrypt(const Data &data);
	Data decrypt(const Data &data);
	string encrypt(const string &data);
	string decrypt(const string &data);
	vector<bool> encrypt(const vector<bool> &data);
	vector<bool> decrypt(const vector<bool> &data);

	const static int BLOCK_SIZE;
	const static int SUBKEY_SIZE;
	const static vector<int> IP_TABLE;
	const static vector<int> IP_TABLE_REVERSED;
	const static vector<int> P_TABLE;
	const static vector<vector<int>> SIX_TO_FOUR_TABLES;
	const static vector<int> E_EXPAND_TABLE;
	const static vector<int> PC_1_LEFT;
	const static vector<int> PC_1_RIGHT;
	const static vector<int> PC_2;
};
