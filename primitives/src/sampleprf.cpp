/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2017 MPC-PRIMITIVES ()
* This file is part of the MPC-PRIMTIVES project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on MPC-PRIMTIVES contain an appropriate citation to MPC-PRIMITIVES, including a reference to
* 
* 
* MPC-PRIMITIVES uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://raw.githubusercontent.com/cris-iisc/mpc-primitives/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/



#include "../headers/sampleprf.hpp"
#include <algorithm>

/*************************************************/
/**** OpenSSLPRP ***/
/*************************************************/

SecretKey PrfPRP::keyGen(int keySize) {
	
	//Generate random bytes to set as the key.
	vector<byte> vec(keySize / 8);
	prg->streamPRGBytes(vec, 0, keySize / 8);
	SecretKey sk(vec, getAlgorithmName());
	return sk;

}

void PrfPRP::computePRFBlock(const vector<byte> & inBytes, int inOff, vector<byte> &outBytes, int outOff) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	
	// Checks that the offset and length are correct.
	if ((inOff > (int)inBytes.size()) || (inOff + getPRFBlockSize() > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	
	const byte* input = & inBytes[inOff];
	
	int size;
	int blockSize = getPRFBlockSize();

	//Make anough space in the output vector.
	if ((int) outBytes.size() - outOff < blockSize)
		outBytes.resize(outOff + blockSize);
	
	// Compute the prp on the given input array, put the result in ret.
	EVP_EncryptUpdate(computeP, outBytes.data() + outOff, &size, input, blockSize);

}

void PrfPRP::optimizedCompute(const vector<byte> & inBytes, vector<byte> &outBytes) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	
	if ((inBytes.size() % getPRFBlockSize()) != 0)
		throw out_of_range("inBytes should be aligned to the block size");
	
	int size = inBytes.size();

	//Make anough space in the output vector.
	if ((int) outBytes.size() < size)
		outBytes.resize(size);
	
	// Compute the prp on each block and put the result in the output array.
	EVP_EncryptUpdate(computeP, outBytes.data(), &size, &inBytes[0], size);

}

void PrfPRP::computePRFBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> &outBytes, int outOff, int outLen) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	
	// the checks on the offset and length are done in the computeBlock(inBytes, inOff, outBytes, outOff).
	if (inLen == outLen && inLen == getPRFBlockSize()) //Checks that the lengths are the same as the block size.
		computePRFBlock(inBytes, inOff, outBytes, outOff);
	else
		throw out_of_range("Wrong size");

}


void PrfPRP::computePRFBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> &outBytes, int outOffset) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	
	// The checks on the offset and length is done in the computeBlock (inBytes, inOffset, outBytes, outOffset).
	if (inLen == getPRFBlockSize()) //Checks that the input length is the same as the block size.
		computePRFBlock(inBytes, inOffset, outBytes, outOffset);
	else
		throw out_of_range("Wrong size");

}

void PrfPRP::invertPRFBlock(const vector<byte> & inBytes, int inOffset, vector<byte>& outBytes, int outOffset) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	
	// Checks that the offsets are correct. 
	if ((inOffset > (int)inBytes.size()) || (inOffset + getPRFBlockSize() > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	
	//Make anough space in the output vector.
	if ((int) outBytes.size() - outOffset < getPRFBlockSize())
		outBytes.resize(getPRFBlockSize() + outOffset);
	
	int size;

	//Invert the prp on the given input array, put the result in ret.
	EVP_DecryptUpdate(invertP, outBytes.data(), &size, &inBytes[inOffset], getPRFBlockSize());

}

void PrfPRP::optimizedInvertBlock(const vector<byte> & inBytes, vector<byte> &outBytes) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	
	if ((inBytes.size() % getPRFBlockSize()) != 0) 
		throw out_of_range("inBytes should be aligned to the block size");
	
	int size = inBytes.size();
	
	//Make anough space in the output vector.
	if ((int) outBytes.size()< size)
		outBytes.resize(size);
	
	// compute the prp on each block and put the result in the output array.
	EVP_DecryptUpdate(invertP, outBytes.data(), &size, &inBytes[0], size);

}

void PrfPRP::invertPRFBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff, int len) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	
	// the checks of the offset and lengths are done in the invertPRFBlock(inBytes, inOff, outBytes, outOff)
	if (len == getPRFBlockSize()) //Checks that the length is the same as the block size
		invertPRFBlock(inBytes, inOff, outBytes, outOff);
	else
		throw out_of_range("Wrong size");

}


PrfPRP::~PrfPRP() {
	
	//Delete the underlying Openssl's objects.
	EVP_CIPHER_CTX_cleanup(computeP);
	EVP_CIPHER_CTX_cleanup(invertP);
	EVP_CIPHER_CTX_free(computeP);
	EVP_CIPHER_CTX_free(invertP);

}

/*************************************************/
/**** OpenSSLAES ***/
/*************************************************/

OpenSSLAES::OpenSSLAES(const shared_ptr<PrgFromAES> & setRandom) {
	
	//Create the underlying Openssl's AES objects.
	prg = setRandom;
	computeP = EVP_CIPHER_CTX_new();
	invertP = EVP_CIPHER_CTX_new();

}

void OpenSSLAES::setPRFKey(SecretKey & secretKey) {
	
	auto keyVec = secretKey.getEncoded();
	int len = keyVec.size();
	
	// AES key size should be 128/192/256 bits long.
	if (len != 16 && len != 24 && len != 32)
		throw InvalidKeyException("AES key size should be 128/192/256 bits long");

	// Set the key to the underlying objects.
	byte* keyBytes = &keyVec[0];
	int bitLen = len * 8; //number of bits in key.

	// Create the requested block cipher.
	const EVP_CIPHER* cipher=NULL;
	switch (bitLen) {
	
	case 128: cipher = EVP_aes_128_ecb();
		break;
	
	case 192: cipher = EVP_aes_192_ecb();
		break;
	
	case 256: cipher = EVP_aes_256_ecb();
		break;
	
	default: break;

	}

	// Initialize the AES objects with the key.
	EVP_EncryptInit(computeP, cipher, keyBytes, NULL);
	EVP_DecryptInit(invertP, cipher, keyBytes, NULL);

	// Set the AES objects with NO PADDING.
	EVP_CIPHER_CTX_set_padding(computeP, 0);
	EVP_CIPHER_CTX_set_padding(invertP, 0);

	_isKeyDefined = true;

}

/*************************************************/
/**** OpenSSLHMAC ***/
/*************************************************/
OpenSSLHMAC::OpenSSLHMAC(string hashName, const shared_ptr<PrgFromAES> & random) {
	
	//Create the underlying Openssl's Hmac object.
	hmac = new  HMAC_CTX;
	OpenSSL_add_all_digests();
	HMAC_CTX_init(hmac);

	/*
	* The way we call the hash is not the same as OpenSSL. For example: we call "SHA-1" while OpenSSL calls it "SHA1".
	* So the hyphen should be deleted.
	*/
	hashName.erase(remove(hashName.begin(), hashName.end(), '-'), hashName.end());
	
	// Get the underlying hash function.
	const EVP_MD *md = EVP_get_digestbyname(hashName.c_str());

	// Create an Hmac object and initialize it with the created hash and default key.
	int res = HMAC_Init_ex(hmac, "012345678", 0, md, NULL);
	
	if (0 == res)
		throw runtime_error("failed to create hmac");

	this->random = random;

}

void OpenSSLHMAC::setPRFKey(SecretKey & secretKey) {
	
	// Initialize the Hmac object with the given key.
	auto secVec = secretKey.getEncoded();
	HMAC_Init_ex(hmac, &secVec[0], secVec.size(), NULL, NULL);
	_isKeyDefined = true;

}

string OpenSSLHMAC::getAlgorithmName() {
	
	int type = EVP_MD_type(hmac->md);
	
	// Convert the type to a name.
	const char* name = OBJ_nid2sn(type);
	return "Hmac/" + string(name);

}

void OpenSSLHMAC::computePRFBlock(const vector<byte> & inBytes, int inOff, vector<byte> &outBytes, int outOff) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");

	throw out_of_range("Size of input is not specified");

}

void OpenSSLHMAC::computePRFBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> &outBytes, int outOff, int outLen) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");

	// The checks of the offsets and lengths are done in the conputeBlock (inBytes, inOff, inLen, outBytes, outOff).
	// make sure the output size is correct.
	if (outLen == getPRFBlockSize())
		computePRFBlock(inBytes, inOff, inLen, outBytes, outOff);
	else
		throw out_of_range("Output size is incorrect");

}

void OpenSSLHMAC::computePRFBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> &outBytes, int outOffset) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	
	// Check that the offset and length are correct.
	if ((inOffset > (int) inBytes.size()) || (inOffset + inLen > (int) inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	
	// Update the Hmac object.
	HMAC_Update(hmac, &inBytes[inOffset], inLen);

	int size = EVP_MD_size(hmac->md);	// Get the size of the hash output.
	if ((int)outBytes.size() < outOffset + size)
		outBytes.resize(outOffset + size);

	//Compute the final function and copy the output the the given output array.
	if (0 == (HMAC_Final(hmac, outBytes.data(), NULL)))
		throw runtime_error("failed to init hmac object");

	// initialize the Hmac again in order to enable repeated calls.
	if (0 == (HMAC_Init_ex(hmac, hmac->key, hmac->key_length, hmac->md, NULL)))
		throw runtime_error("failed to init hmac object");

}

SecretKey OpenSSLHMAC::keyGen(int keySize) {
	
	

	// If the key size is zero or less - throw exception.
	if (keySize <= 0)
		throw invalid_argument("key size must be greater than 0");

	// The key size has to be a multiple of 8 so that we can obtain an array of random bytes which we use
	// to create the SecretKey.
	if ((keySize % 8) != 0)
		throw invalid_argument("Wrong key size: must be a multiple of 8");

	vector<byte> genBytes(keySize / 8); // Creates a byte vector of size keySize.
	random->streamPRGBytes(genBytes, 0, keySize / 8);	// Generates the bytes using the random.
	
	return SecretKey(genBytes.data(), keySize/8, "");

}

vector<byte> OpenSSLHMAC::macSign(const vector<byte> &msg, int offset, int msgLen) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	
	// Creates the tag.
	vector<byte> tag(getMacInputBlockSize());
	
	// Computes the hmac operation.
	computePRFBlock(msg, offset, msgLen, tag, 0);
	
	//Returns the tag.
	return tag;

}

bool OpenSSLHMAC::macVerify(const vector<byte> &msg, int offset, int msgLength, vector<byte>& tag) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	
	// If the tag size is not the mac size - returns false.
	if ((int) tag.size() != getMacInputBlockSize())
		return false;
	
	// Calculate the mac on the msg to get the real tag.
	vector<byte> macTag = macSign(msg, offset, msgLength);

	// Compares the real tag to the given tag.
	// for code-security reasons, the comparison is fully performed. that is, even if we know already after the first few bits 
	// that the tag is not equal to the mac, we continue the checking until the end of the tag bits.
	bool equal = true;
	int length = macTag.size();
	
	for (int i = 0; i<length; i++) {
		if (macTag[i] != tag[i]) {
			equal = false;
		}

	}

	return equal;

}



void OpenSSLHMAC::updateMac(vector<byte> & msg, int offset, int msgLen) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");

	// Update the Hmac object.
	HMAC_Update(hmac, &msg[offset], msgLen);

}



void OpenSSLHMAC::macToTag(vector<byte> & msg, int offset, int msgLength, vector<byte> & tag_res) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	
	// Update the last msg block.
	updateMac(msg, offset, msgLength);

	if ((int) tag_res.size() < getMacInputBlockSize())
		tag_res.resize(getMacInputBlockSize());

	// compute the final function and copy the output the the given output array
	if (0 == (HMAC_Final(hmac, tag_res.data(), NULL)))
		throw runtime_error("failed to init hmac object");

	//initialize the Hmac again in order to enable repeated calls.
	if (0 == (HMAC_Init_ex(hmac, hmac->key, hmac->key_length, hmac->md, NULL)))
		throw runtime_error("failed to init hmac object");

}

OpenSSLHMAC::~OpenSSLHMAC()
{
	//Delete the underlying openssl's object.
	HMAC_CTX_cleanup(hmac);
	delete hmac;
}

/*************************************************/
/**** OpenSSLTripleDES ***/
/*************************************************/

OpenSSLTripleDES::OpenSSLTripleDES() {
	
	// Create the underlying openssl's objects.
	computeP = EVP_CIPHER_CTX_new();
	invertP = EVP_CIPHER_CTX_new();
	prg = get_seeded_prg();

}

void OpenSSLTripleDES::setPRFKey(SecretKey & secretKey) {
	
	vector<byte> keyBytesVector = secretKey.getEncoded();
	int len = keyBytesVector.size();

	// TripleDES key size should be 128/192 bits long.
	if (len != 16 && len != 24)
		throw InvalidKeyException("TripleDES key size should be 128/192 bits long");

	// Create the requested block cipher.
	const EVP_CIPHER* cipher = EVP_des_ede3();

	// Initialize the Triple DES objects with the key.
	EVP_EncryptInit(computeP, cipher, &keyBytesVector[0], NULL);
	EVP_DecryptInit(invertP, cipher, &keyBytesVector[0], NULL);

	// Set the Triple DES objects with NO PADDING.
	EVP_CIPHER_CTX_set_padding(computeP, 0);
	EVP_CIPHER_CTX_set_padding(invertP, 0);
	_isKeyDefined= true;

}

std::shared_ptr<PseudorandomFunction> PseudorandomFunction::get_new_prf(string algName) {
	
	if (algName == "AES")
		return make_shared<OpenSSLAES>();
	
	if (algName == "TripleDES")
		return make_shared<OpenSSLTripleDES>();
	
	if (algName == "HMAC")
		return make_shared<OpenSSLHMAC>();
	
	// Wrong algorithm name
	throw invalid_argument("unexpected prf name");

}