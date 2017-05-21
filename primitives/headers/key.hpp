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

#ifndef CRISMPC_KEY_H
#define CRISMPC_KEY_H

#include "exception.hpp"

class Key {

public:
	/*
	* Returns the name of the algorithm associated with this key.
	*/
	virtual string getAlgorithm()=0;

	//method to encode key
	virtual vector<byte> getEncoded()=0;

	//Destructor
	virtual ~Key() {};

}; //endofclass


/*class to provide secret key for communication. Inherits from Key*/
class SecretKey : Key {
	
	friend class boost::serialization::access;
	
private:
	vector<byte> key;
	string algorithm;

public:
	//default constructor
	SecretKey() {};

	//parametrized constructor to initialize members
	SecretKey(byte * keyBytes, int keyLen, string algorithm) {
		
		copy_byte_array_to_byte_vector(keyBytes, keyLen, this->key, 0);
		this->algorithm = algorithm;

	}

	//overloaded parametrized constructor
	SecretKey(const vector<byte> & key, string algorithm) {
		
		this->key = key;
		this->algorithm = algorithm;

	};

	//method to obtain the name of the algorithm that uses the key
	string getAlgorithm() override { 
		
		return algorithm; 

	};

	//Overridden method to encode the key
	vector<byte> getEncoded() override { 
		
		return key; 

	};
	
	//destructor
	virtual ~SecretKey() {};
	
	template<class Archive>
	//Serializing the key and algorithm
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & key;
		ar & algorithm;
	}

};//endofclass

/*Class for symmetric key cryptosystems, Inherits Secret key*/
class SymmetricKeyCryptoKey : SecretKey {

}; //endofclass


/*Class to implement a public key */
class PublicKey : public Key {};

/*Class to implement a private key */
class PrivateKey : public Key {};

/*class KeySendableData : public NetworkSerialized {};

class KeySpec {};*/

/*Class for public key cryptosystems, uses has a relationship with classes PublicKey and PrivateKey class */
class PublicKeyCryptoKeyPair {

private:
	PublicKey * publicKey;
	PrivateKey * privateKey;

public:
	//constructor
	PublicKeyCryptoKeyPair(PublicKey * pubk, PrivateKey * pvk) {
		
		publicKey = pubk;
		privateKey = pvk;
	};

	//Get methods for accessing private members
	PublicKey * GetPublic() { 
		return publicKey; 

	};

	PrivateKey * GetPrivate() { 
		return privateKey; 
	};

};//endofclass


/*Class for Building RSA Key */
class RSAKey {

private:
	biginteger modulus;

public:
	//constructor
	RSAKey(biginteger mod) { 
		
		modulus = mod; 

	};

	//get method to access private members
	biginteger getModulus() { 
		
		return modulus; 

	};

}; //endofclass

/*Class for building RSA public key */
class RSAPublicKey : public RSAKey, public PublicKey {

private:
	biginteger publicExponent;

public:
	//constructor
	RSAPublicKey(biginteger mod, biginteger pubExp) : RSAKey(mod) { 
		
		publicExponent = pubExp;
	};

	//get methods to access private members
	biginteger getPublicExponent() { 
		
		return publicExponent; 
	};

	string getAlgorithm() override { 
		
		return "RSA";

	};

	vector<byte> getEncoded() override { 
		
		throw NotImplementedException(""); 

	};

}; //endofclass


/*Class for building RSA private key*/
class RSAPrivateKey : public RSAKey, public PrivateKey {

private:
	biginteger privateExponent;

public:
	//constructor
	RSAPrivateKey(biginteger mod, biginteger privExp) : RSAKey(mod) { 
		
		privateExponent = privExp; 
	
	};

	//get methods for accessing private members
	biginteger getPrivateExponent() { 

		return privateExponent;

	};

	string getAlgorithm() override { 
		
		return "RSA";

	};

	vector<byte> getEncoded() override { 

		throw NotImplementedException(""); 

	};

};


/*Class for RSA private key from primes*/
class RSAPrivateCrtKey : public RSAPrivateKey {

public:
	virtual biginteger getPublicExponent() = 0;
	virtual biginteger getPrimeP() = 0;
	virtual biginteger getPrimeQ() = 0;
	virtual biginteger getPrimeExponentP() = 0;
	virtual biginteger getPrimeExponentQ() = 0;
	virtual biginteger getCrtCoefficient() = 0;

}; //endofclass

/*Class for specifying param specs of a primitive/protocol */
class AlgorithmParameterSpec {

public: 
	virtual ~AlgorithmParameterSpec(){}

}; //endofclass

/*CLass for specifying param specs of RSA  */
class RSAKeyGenParameterSpec : public AlgorithmParameterSpec {};

#endif
