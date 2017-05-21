#pragma once

#define WIN32_LEAN_AND_MEAN

#include <boost/random.hpp>
#ifdef _WIN32
#include <boost/multiprecision/cpp_int.hpp>
#else
#include <boost/multiprecision/gmp.hpp>
#endif
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/timer/timer.hpp>
#include <math.h> /* pow */
#include <random>
#include <memory>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <chrono>

#include <boost/serialization/serialization.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/shared_ptr.hpp>
#include <boost/serialization/export.hpp>


using namespace std;

class IllegalStateException : public logic_error
{
public:
	IllegalStateException(const string & msg) : logic_error(msg) {};
};

class NotImplementedException : public logic_error
{
public:
	NotImplementedException(const string & msg) : logic_error(msg) {};
};

class InvalidKeyException : public logic_error
{
public:
	InvalidKeyException(const string & msg) : logic_error(msg) {};
};

class KeyException : public logic_error
{
public:
	KeyException(const string & msg) : logic_error(msg) {};
};

class UnsupportedOperationException : public logic_error
{
public:
	UnsupportedOperationException(const string & msg) : logic_error(msg) {};
};

class SecurityLevelException : public logic_error
{
public:
	SecurityLevelException(const string & msg) : logic_error(msg) {};
};

class CheatAttemptException : public logic_error
{
public:
	CheatAttemptException(const string & msg) : logic_error(msg) {};
};

class TimeoutException : public logic_error
{
public:
	TimeoutException(const string & msg) : logic_error(msg) {};
};

class DuplicatePartyException : public logic_error
{
public:
	DuplicatePartyException(const string & msg) : logic_error(msg) {};
};

class PartyCommunicationException : public logic_error
{
public:
	PartyCommunicationException(const string & msg) : logic_error(msg) {};
};



// using boost::multiprecision:cpp_int - Arbitrary precision integer type.
namespace mp = boost::multiprecision;     // reduce the typing a bit later...

#ifdef _WIN32
using biginteger = boost::multiprecision::cpp_int;
#else
using biginteger = boost::multiprecision::mpz_int;
#endif

typedef unsigned char byte;		// put in global namespace to avoid ambiguity with other byte typedefs


int find_log2_floor(biginteger);
int NumberOfBits(const biginteger & bi);

/*
* Retruns the number of bytes needed to represent a biginteger
* Notice that due to the sign number of byte can exceed log(value)
*/
size_t bytesCount(const biginteger & value);

class PrgFromAES;

shared_ptr<PrgFromAES> get_seeded_prg();

void copy_byte_vector_to_byte_array(const vector<byte> &source_vector, byte * dest, int beginIndex);
void copy_byte_array_to_byte_vector(const byte* src, int src_len, vector<byte>& target_vector, int beginIndex);

/*
* Converting big integer to a byte array. Array must be allocated already
* Number can be postive or negative - the sign will be preserved in the encoding
* Use byteCount(biginteger) method to calculate the number of bytes needed.
*/
void encodeBigInteger(const biginteger & value, byte* output, size_t length);

/*
* Decodoing big integer from byte array back to a biginteger object
*/
biginteger decodeBigInteger(const byte* input, size_t length);

biginteger convert_hex_to_biginteger(const string & hex);

/*
* Returns a random biginteger uniformly distributed in [min, max]
*/
biginteger getRandomInRange(const biginteger & min, const biginteger & max, PrgFromAES* random);

/*
* Returns a random prime number with the given number of bytes.
*/
biginteger getRandomPrime(int numBytes, int certainty, PrgFromAES* random);
const vector<string> explode(const string& s, const char& c);

bool isPrime(const biginteger & bi, int certainty = 40);

/********************/
/* Debugging Methods*/
/********************/

void print_elapsed_ms(std::chrono::time_point<std::chrono::system_clock> start, string message);
void print_elapsed_micros(std::chrono::time_point<std::chrono::system_clock> start, string message);
std::chrono::time_point<std::chrono::system_clock> scapi_now();
string hexStr(vector<byte> const & data);
void print_byte_array(byte * arr, int len, string message);
void gen_random_bytes_vector(vector<byte> &v, const int len, PrgFromAES* random);

/**
* Abstract marker interface that allow serialization and deserialization from byte array and size
*/
class NetworkSerialized {
public:
	virtual string toString() = 0;
	virtual void initFromString(const string & raw) = 0;
	virtual void initFromByteVector(const vector<byte> & byteVector) {
		const byte * uc = &(byteVector[0]);
		std::string s(reinterpret_cast<char const*>(uc), byteVector.size());
		initFromString(s);
	}
};

