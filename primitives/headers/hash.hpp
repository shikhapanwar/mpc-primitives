/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
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
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


#ifndef CRISMPC_HASH_H
#define CRISMPC_HASH_H

#include <openssl/evp.h>
#include <set>
#include "exception.hpp"
#include "securitynotion.hpp"

/**
* A hash function is target collision resistant if it is infeasible for an adversary to succeed in the following game:
* the adversary chooses a message x;
* next a random key K is chosen for the hash function and given to the adversary;
* finally the adversary outputs some y (not equal to x) such that H_K(x)=H_K(y).<p>
* Observe that this notion is of relevance for KEYED hash functions (note that the key is public, but randomly chosen).
*/
class TargetCollisionResistantHash : HashSecurity {};

/**
* A hash function H is collision resistant if it is infeasible to find two distinct values x and y such that H(x)=H(y).
*/
class CollisionResistantHash : TargetCollisionResistantHash {};

/**
* Abstract class for CryptographicHash. Every concrete class should derive this class. <p>
* A cryptographic hash function is a deterministic procedure that takes an arbitrary block of data and returns a fixed-size bit string,
* the (cryptographic) hash value.
*/
class CryptographicHash {
public:
	virtual ~CryptographicHash() {};

	/**
	* @return The algorithm name. For example - SHA1.
	*/
	virtual string getAlgorithmName()=0;

	/**
	* @return the size of the hashed massage in bytes.
	*/
	virtual int getHashedMsgSize()=0;

	/**
	* Adds the byte vector to the existing message to hash.
	* @param in input byte vector.
	* @param inOffset the offset within the byte array.
	* @param inLen the length. The number of bytes to take after the offset.
	* */
	virtual void updateHash(const vector<byte> &in, int inOffset, int inLen)=0;

	/**
	* Completes the hash computation and puts the result in the out vector.
	* @param out the output in byte vector.
	* @param outOffset the offset which to put the result bytes from.
	*/
	virtual void outputHash(vector<byte> &out, int outOffset)=0;

	/**
	* Factory method. Create concrete instance of the give algorithm name in the default implementation. 
	*/
	static shared_ptr<CryptographicHash> get_new_cryptographic_hash(string hash_name="SHA256");
};

/*****************************************************************
* SHA Abstract classes. Every class that implements them is signed as SHA:
******************************************************************/
class AbstractSHA1   : public virtual CryptographicHash, public virtual CollisionResistantHash {};
class AbstractSHA224 : public virtual CryptographicHash, public virtual CollisionResistantHash {};
class AbstractSHA256 : public virtual CryptographicHash, public virtual CollisionResistantHash {};
class AbstractSHA384 : public virtual CryptographicHash, public virtual CollisionResistantHash {};
class AbstractSHA512 : public virtual CryptographicHash, public virtual CollisionResistantHash {};

/**
* A general adapter class of hash for OpenSSL. <p>
* This class implements all the functionality by passing requests to the adaptee OpenSSL functions,
* like int SHA1_Update(SHA_CTX *c, const void *data, unsigned long len);.
*
* A concrete hash function such as SHA1 represented by the class OpenSSLSHA1 only passes the name of the hash in the constructor
* to this base class.
*/
class Hash : public virtual CryptographicHash {
private:
	int hashSize;
protected:
	shared_ptr<EVP_MD_CTX> hash; //Pointer to the OpenSSL hash object.
public:
	/**
	* Constructs the OpenSSL hash object.
	* @param hashName - the name of the hash. This will be passed to the jni dll function createHash so it will know which hash to create.
	*/
	Hash(string hashName);

	/**
	* @return the size of the hashed massage in bytes.
	*/
	int getHashedMsgSize() override { 
		
		return hashSize;

	};

	string getAlgorithmName() override;

	/**
	* Adds the byte vector to the existing message to hash.
	* @param in input byte vector.
	* @param inOffset the offset within the byte array.
	* @param inLen the length. The number of bytes to take after the offset.
	* */
	void updateHash(const vector<byte> &in, int inOffset, int inLen) override;

	/**
	* Completes the hash computation and puts the result in the out vector.
	* @param out the output in byte vector.
	* @param outOffset the offset which to put the result bytes from.
	*/
	void outputHash(vector<byte> &out, int outOffset) override;
};

/************************************************************
* Concrete classes of cryptographicHash for different SHA. 
* These classes wrap OpenSSL implementation of SHA*.
*************************************************************/

class SHA1 : public Hash , public AbstractSHA1 {
public:
	SHA1() : Hash("SHA1") {};
};

class SHA224 : public Hash, public AbstractSHA224 {
public:
	SHA224() : Hash("SHA224") {};
};

class SHA256 : public Hash, public AbstractSHA256{
public:
	SHA256() : Hash("SHA256") {};
};

class SHA384 : public Hash, public AbstractSHA384 {
public:
	SHA384() : Hash("SHA384") {};
};

class SHA512 : public Hash, public AbstractSHA512 {
public:
	SHA512() : Hash("SHA512") {};
};



#endif
