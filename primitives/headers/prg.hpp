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


#ifndef SCAPI_PRG_H
#define SCAPI_PRG_H

#include "key.hpp"
#include "prf.hpp"
#include <openssl/rc4.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <emmintrin.h>


typedef unsigned char byte;
typedef __m128i block;

#define DEFAULT_NUM_OF_RANDOMS 12800
#define BLOCK_SIZE 16

/**
* Parameters for PrgFromPrf key generation.
*/
class PrgFromPrfParameterSpec : public AlgorithmParameterSpec {

private:
	vector<byte> entropySource;	// Random bit sequence.
	int prfKeySize;				// Prf key size in bits.

public:	

	/**
	* Constructor that gets a random bit sequence which is the entropy source, and prf key size in 
	* bits and sets them.
	*/
	PrgFromPrfParameterSpec(vector<byte> &entropySource, int prfKeySize) {
		this->entropySource = entropySource;
		this->prfKeySize = prfKeySize;
	};
	vector<byte> getEntropySource() { 
		
		return entropySource; 

	};

	int getPrfKeySize() { 
		
		return prfKeySize; 
	};

};

/**
* Abstract class of pseudorandom generator. Every concrete class in this family should derive this class. 
*
* A pseudorandom generator (PRG) is a deterministic algorithm that takes a short uniformly distributed string,
* known as the seed, and outputs a longer string that cannot be efficiently distinguished from a uniformly
* distributed string of that length.
*/
class PseudorandomGenerator {
public:
	/**
	* Sets the secret key for this prg.
	* The key can be changed at any time.
	*/
	virtual void setPRGKey(SecretKey & secretKey)=0;
	
	/**
	* An object trying to use an instance of prg needs to check if it has already been initialized with a key.
	* @return true if the object was initialized by calling the function setKey.
	*/
	virtual bool isKeyDefined()=0;
	
	/**
	* @return the algorithm name. For example - RC4
	*/
	virtual string getAlgorithmName()=0;
	
	/**
	* Generates a secret key to initialize this prg object.
	* @param keyParams algorithmParameterSpec contains the required parameters for the key generation
	* @return the generated secret key
	*/
	virtual SecretKey KeyGen(AlgorithmParameterSpec & keyParams)=0;
	
	/**
	* Generates a secret key to initialize this prg object.
	* @param keySize is the required secret key size in bits
	* @return the generated secret key
	*/
	virtual SecretKey KeyGen(int keySize)=0;
	
	/**
	* Streams the prg bytes.
	* @param outBytes - output bytes. The result of streaming the bytes.
	* @param outOffset - output offset
	* @param outlen - the required output length
	*/
	virtual void getPRGBytes(vector<byte> & outBytes, int outOffset, int outlen)=0;

};



/**
* This is a simple way of generating a pseudorandom stream from a pseudorandom function.
* The seed for the pseudorandom generator is the key to the pseudorandom function.
* Then, the algorithm initializes a counter to 1 and applies the pseudorandom function to the counter, 
* increments it, and repeats.
*/
class PrgFromPrf : public PseudorandomGenerator {

private:
	shared_ptr<PseudorandomFunction> prf;	// Underlying PRF.
	vector<byte> ctr;						// Counter used for key generation.
	bool _isKeyDefined=false;
	
	/**
	* Increases the ctr byte array by 1 bit.
	*/
	void increaseCtr();

public:
	/**
	* Constructor that lets the user choose the underlying PRF algorithm.
	* @param prf underlying PseudorandomFunction.
	*/
	PrgFromPrf(const shared_ptr<PseudorandomFunction> & prf) {

		this->prf = prf;

	};
	
	/**
	* Constructor that lets the user choose the underlying PRF algorithm.
	* @param prfName PseudorandomFunction algorithm name.
	*/
	PrgFromPrf(string prfName) : PrgFromPrf(PseudorandomFunction::get_new_prf(prfName)) {};

	void setPRGKey(SecretKey & secretKey) override;

	bool isKeyDefined() override { 
		
		return _isKeyDefined; 

	};

	string getAlgorithmName() override { 
		
		return "PRG_from_" + prf->getAlgorithmName(); 

	};

	SecretKey KeyGen(AlgorithmParameterSpec & keyParams) override { 
		
		return prf->KeyGen(keyParams); 

	};

	SecretKey KeyGen(int keySize) override { 
		
		return prf->KeyGen(keySize); 

	};
	
	void getPRGBytes(vector<byte> & outBytes, int outOffset, int outLen) override;


};

/**
* This pseudorandom generator is based on the aes block cipher with the ecb mode of openssl.
* The class holds two main arrays, one for the plaintext and one for the ciphertext where the cihpertext produced
* by calling aes with ecb mode has holds the randomness. Since calling ecb mode with the same plaintext produces 
* the same ciphertext, the plaintext is an array of indices starting from 0 at the begining and is incremented
* when the prg runs out or randoms and new call to aes with ecb is required.
* The seed for the pseudorandom generator is the key to the underlying aes and if two prg are set with the same 
* key, they generated the same randoms.
*/
class PrgFromAES : public PseudorandomGenerator {
private:
	// Counter used for key generation.
	block iv = _mm_setzero_si128();

	int cachedSize;
	int idxForBytes = 0;
	int startingIndex = 0;
	EVP_CIPHER_CTX *aes = nullptr;
	bool _isKeyDefined = false;
	block* cipherChunk;
	block* indexPlaintext;
	bool isStrict;

public:
	/**
	* This constructor does the following.
	*	 - allocates counter array (plaintext) and ciphertext array.
	*	 - initialize the counter array (64 high bits zero, 64 low bits incrementing counter)
	* @param cachedSize - the number of randoms generated in advence which also determines the size of the 
						  ciphertext and plaintext arrays
	* @param isStrict - a flag that indicates whether new fresh randoms will be generated when the ciphertext randoms
	*					are all used up, or throws an exception if the user asks for more randoms.
	*					If isStrict is true, the user can only use cachedSize*16 random bytes.		
	*/
	PrgFromAES( int cachedSize = DEFAULT_NUM_OF_RANDOMS, bool isStrict = false);

	//move assignment
	PrgFromAES& operator=(PrgFromAES&& other);

	//copy assignment - not allowed to prevent unneccessary copy of arrays.
	PrgFromAES& operator=(PrgFromAES& other) = delete;
	
	//move constructor
	PrgFromAES(PrgFromAES&& old);
	//copy constructor - not allowed to prevent unneccessary copy of arrays.
	PrgFromAES(PrgFromAES& other) = delete;

	~PrgFromAES();
	
	/**
	* This function does the following.
	* - Calls OpenSSL init function to create the key schedule. 
	* - Performs the encryption to fill in the cypherbits array
	*  @param secretKey - the new secret key for the aes to set.
	*/
	void setPRGKey(SecretKey & secretKey) override;
	
	bool isKeyDefined() override { 
		
		return _isKeyDefined; 

	};

	string getAlgorithmName() override { 
		
		return "PrgFromOpenSSLAES"; 

	};

	SecretKey KeyGen(AlgorithmParameterSpec & keyParams) override {
		
		throw NotImplementedException("To generate a key for this prg object use the generateKey(int keySize) function");
	
	}

	SecretKey KeyGen(int keySize) override;

	/**
	* Fill the out vector with random bytes. This bytes are set to used and will not be used again
	* @param outBytes - output random bytes pre-generated by the prg 
	* @param outOffset - output offset
	* @param outlen - the required output length
	*/
	void getPRGBytes(vector<byte> & outBytes, int outOffset, int outLen) override;

	/**
	* @returns a random variable of the required length (32,64,128). This bytes are set to used and will not be used again
	* Note that if all the randoms are used a new fresh randoms are genereted unless the isStrict flag is set to true
	*/
	uint32_t getRandom32();
	uint64_t getRandom64();
	block getRandom128();


	/**
	* This function does the following.
	* -Allocates a fresh set of randoms
	* -if not all randoms have been consumed before call, they may be discarded
	*
	* If isStrict is set to true an exception is thrown
	*/
	void prepare();

};

/**
* This class wraps the OpenSSL implementation of RC4.
* RC4 is a well known stream cipher, that is essentially a pseudorandom generator.
* In our implementation, we throw out the first 1024 bits since the first few bytes have been shown
* to have some bias.
**/


/**
 * This class implements a singleton design pattern for PrgFromOpenSSLAES.
 * An instance of PrgFromOpenSSLAES is created in the first time of getInstance is called.
 * After that, every call to the getInstance return this object.
 */
class PrgSingleton {

private:
	static shared_ptr<PrgFromAES> prg; //Instance to return in getInstance function.
	
	/**
	* The constructor is private to disable creation objects of the class.
	*/
	PrgSingleton() {}
public:

	/**
	* Static function that return the instance PrgFromOpenSSLAES.
	* If it is the first time, create the instance and return it.
	* Else, just return the instance.
	*/
	static shared_ptr<PrgFromAES> getInstance() { 
		if (prg == nullptr) {
			prg = make_shared<PrgFromAES>();
			auto key = prg->KeyGen(128);
			prg->setPRGKey(key);
		}
		return prg; 
	}
	
};

#endif
