#include "Crypto.h"
#include <exception>
#include <vector>
#include <list>
#include <initializer_list>
#include <algorithm>

const int Crypto::BLOCK_SIZE = 64;
const int Crypto::SUBKEY_SIZE = 48;

const vector<int> Crypto::IP_TABLE = { 58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7 };
const vector<int> Crypto::IP_TABLE_REVERSED = { 40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25 };
const vector<int> Crypto::E_EXPAND_TABLE = { 32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1 };
const vector<int> Crypto::P_TABLE = { 16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25 };
const vector<vector<int>> Crypto::SIX_TO_FOUR_TABLES = {
	{ 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 },
	{ 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 },
	{ 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 },
	{ 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 },
	{ 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 },
	{ 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 },
	{ 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 },
	{ 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
};
const vector<int> Crypto::PC_1_LEFT = { 57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36 };
const vector<int> Crypto::PC_1_RIGHT = { 63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4 };
const vector<int> Crypto::PC_2 = { 14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32 };

Crypto::Crypto(const Data &key) {
	if (key.size() != BLOCK_SIZE) throw invalid_argument("key length must be 64 bits");
	this->key = key;
}

list<Crypto::Data> Crypto::slice(const Data &data) {
	list<Data> result;
	int pos = 0;
	while (pos < data.size()) {
		Data block;
		auto block = padding(makeSubstring(data, pos, BLOCK_SIZE));
		result.push_back(block);
		pos += BLOCK_SIZE;
	}
	return result;
}

Crypto::Data Crypto::stringToBinary(const string &str) {
	Data binary;
	binary.reserve(str.length() * 8);
	for (auto ch : str) {
		for (int i = 0; i < 8; i++) binary.push_back(unsigned char(ch) & (0b1u << i));
	}
}

string Crypto::binaryToString(const Data &data) {
	string str;
	str.reserve(data.size());
	int i = 0;
	while (i < data.size()) {
		unsigned char ch = 0;
		for (int j = 0; j < 8; j++) {
			ch <<= 1;
			ch |= data[i + j];
		}
		str += ch;
		i += 8;
	}
	return str;
}

string Crypto::encrypt(const string &data) {
	auto binary = stringToBinary(data);
	binary = encrypt(binary);
	return binaryToString(binary);
}

string Crypto::decrypt(const string &data) {
	auto binary = stringToBinary(data);
	binary = decrypt(binary);
	return binaryToString(binary);
}

Crypto::Data Crypto::encrypt(const Data &data) {
	list<Data> result;
	auto blocks = slice(data);
	for (const auto &block : blocks) result.push_back(encryptBlock(block));
	return accumulate(result);
}


Crypto::Data Crypto::decrypt(const Data &data) {
	list<Data> result;
	auto blocks = slice(data);
	for (const auto &block : blocks) result.push_back(decryptBlock(block));
	return accumulate(result);
}

Crypto::Data Crypto::encryptBlock(const Data &block) {
	if (block.size() != BLOCK_SIZE) throw invalid_argument("incorrect blocksize");

	Data work = block; // init
	work = initPermute(work); // initial permutation
	work = subKeyIteration(work); // 16 rounds of iteration
	work = initPermuteInverse(work); // reversing initial permutation
	return work;
}

Crypto::Data Crypto::decryptBlock(const Data &block) {
	if (block.size() != BLOCK_SIZE) throw invalid_argument("incorrect blocksize");

	Data work = block; // init
	work = initPermute(work); // initial permutation
	work = subKeyIteration(work, true); // 16 rounds of iteration
	work = initPermuteInverse(work); // reversing initial permutation
	return work;
}

Crypto::Data Crypto::initPermute(const Data &data) {
	return permute(data, IP_TABLE);
}

Crypto::Data Crypto::initPermuteInverse(const Data &data) {
	return permute(data, IP_TABLE_REVERSED);
}

Crypto::Data Crypto::permute(const Data &block, const vector<int> &table) {
	int size = table.size();
	Data result;
	result.resize(size);
	for (int i = 0; i < size; i++) {
		result[i] = block[table[i]];
	}
	return result;
}

Crypto::Data Crypto::subKeyIteration(const Data &block, const bool reversed) {
	auto subKeys = genSubKey();
	if (reversed) subKeys.reverse(); // for decryption
	auto L = makeSubstring(block, 0, BLOCK_SIZE / 2);
	auto R = makeSubstring(block, BLOCK_SIZE / 2, BLOCK_SIZE / 2);
	for (const auto &subKey : subKeys) {
		auto temp = L;
		L = R;
		R = bitwiseXor(temp, FeistelRound(R, subKey));
	}
	return appendData(R, L);
}

Crypto::Data Crypto::bitwiseOr(const Data &a, const Data &b) {
	if (a.size() != b.size()) throw invalid_argument("length not matched");
	auto result = a;
	for (size_t i = 0; i < a.size(); i++) result[i] = result[i] | b[i];
	return result;
}

Crypto::Data Crypto::bitwiseXor(const Data &a, const Data &b) {
	if (a.size() != b.size()) throw invalid_argument("length not matched");
	auto result = a;
	for (size_t i = 0; i < a.size(); i++) result[i] = result[i] ^ b[i];
	return result;
}

Crypto::Data Crypto::FeistelRound(const Data &block, const Data &subKey) {
	if (subKey.size() != SUBKEY_SIZE) throw invalid_argument("incorrect subkey size");
	auto E = eExpand(block);
	E = bitwiseXor(E, subKey);

	auto six = intoSix(E);

	Data result;
	for (size_t i = 0; i < six.size(); i++) {
		appendData(result, sixToFour(six[i], i));
	}

	return pPermute(result);
}

vector<Crypto::Data> Crypto::intoSix(const Data &block) { // 48 bits into 8 * 6 bits
	static const int GROUP_SIZE = 6;
	vector<Data> res;
	int pos = 0;
	while (pos < block.size()) {
		Data tmp;
		tmp.resize(GROUP_SIZE);
		copy_n(block.begin() + pos, GROUP_SIZE, tmp.begin());
		res.push_back(tmp);
		pos += GROUP_SIZE;
	}
	return res;
}

Crypto::Data Crypto::sixToFour(Data bits, int slot) {
	int row = bits[0] + (bits[5] << 1);
	int col = (bits[1] + (bits[2] << 1) + (bits[3] << 2) + (bits[4] << 3));
	int val = SIX_TO_FOUR_TABLES[slot][row * 16 + col];
	return Data({ bool(val & 0b1), bool(val & 0b10) ,bool(val & 0b100) ,bool(val & 0b1000) });
}

Crypto::Data Crypto::eExpand(const Data &block) {
	return permute(block, E_EXPAND_TABLE);
}

Crypto::Data Crypto::pPermute(const Data &block) {
	return permute(block, P_TABLE);
}

list<Crypto::Data> Crypto::genSubKey() {
	static const int SUB_KEY_COUNT = 16;
	auto C = permute(key, PC_1_LEFT);
	auto D = permute(key, PC_1_LEFT);
	list<Data> subKeys;

	for (int i = 1; i <= SUB_KEY_COUNT; i++) {
		switch (i) {
		case 1:
		case 2:
		case 9:
		case 16:
			circularShiftLeft(C, 1);
			circularShiftLeft(D, 1);
			break;
		default:
			circularShiftLeft(C, 2);
			circularShiftLeft(D, 2);
		}
		auto tmp = C;
		subKeys.push_back(permute(appendData(C, D), PC_2));
	}

	return subKeys;
}

Crypto::Data& Crypto::circularShiftLeft(Data &data, int times) {
	for (int i = 0; i < times; i++) {
		bool val = data.front();
		for (size_t i = 0; i < data.size() - 1; i++) data[i] = data[i + 1];
		data.back() = val;
	}
	return data;
}

Crypto::Data Crypto::padding(const Data &block) {
	if (block.size() >= BLOCK_SIZE) throw invalid_argument("block oversized");
	Data res = block;
	res.resize(BLOCK_SIZE, 0);
	return res;
}

Crypto::Data Crypto::accumulate(const list<Data> &li) {
	int len = 0;
	for (auto &s : li) len += s.size();
	Data result;
	result.reserve(len);
	for (auto &s : li) appendData(result, s);
	return result;
}

Crypto::Data Crypto::makeSubstring(const Data &data, int pos, int len) {
	if (pos + len > data.size()) len = data.size() - pos;
	Data result;
	result.resize(len);
	copy_n(data.begin() + pos, len, result.begin());
	return result;
}

Crypto::Data& Crypto::appendData(Data &dest, const Data &append) {
	dest.insert(dest.end(), append.begin(), append.end());
	return dest;
}
