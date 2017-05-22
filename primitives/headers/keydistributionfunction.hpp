

#pragma once



#include <mutex>
#include "prf.hpp"
#include "sampleprf.hpp"


/**
* Abstract class of key derivation function. Every class in this family should derive this class.
* A key derivation function (or KDF) is used to derive (close to) uniformly distributed string/s from a secret value
* with high entropy (but no other guarantee regarding its distribution).
*/
class KeyDerivationFunction {

public:
	/**
	* Generates a new secret key from the given entropy and iv.
	* @param entropySource the byte vector that is the seed for the key generation
	* @param inOff the offset within the entropySource to take the bytes from
	* @param inLen the length of the seed
	* @param outLen the required output key length
	* @param iv info for the key generation
	* @return SecretKey the derivated key.
	*/
	virtual SecretKey deriveKey(const vector<byte> & entropySource, int inOff, int inLen, int outLen, const vector<byte>& iv = vector<byte>()) = 0;

};

/**
* Concrete class of key derivation function for HKDF.
* This is a key derivation function that has a rigorous justification as to its security.
* Note that all deriveKey functions in this implementation are thread safe.
*/
class HKDF : public KeyDerivationFunction {

private:
	shared_ptr<Hmac> hmac; // The underlying hmac
	mutex _mutex; // For synchronizing
	
	/**
	* Does round 2 to t of HKDF algorithm. The pseudo code:
	* FOR i = 2 TO t
	* K(i) = HMAC(PRK,(K(i-1),CTXinfo,i)) [key=PRK, data=(K(i-1),CTXinfo,i)]
	* @param outLen the required output key length
	* @param iv The iv : ctxInfo
	* @param hmacLength the size of the output of the hmac.
	* @param outBytes the result of the overall computation
	* @param intermediateOutBytes round result K(i) in the pseudocode
	*/
	void nextRounds(int outLen, const vector<byte> & iv, int hmacLength, vector<byte> & outBytes, vector<byte> & intermediateOutBytes);
	
	/**
	* First round of HKDF algorithm. The pseudo code:
	* K(1) = HMAC(PRK,(CTXinfo,1)) [key=PRK, data=(CTXinfo,1)]
	* @param iv ctxInfo
	* @param intermediateOutBytes round result K(1) in the pseudocode
	* @param outLength the size of the output of the hmac.
	* @param outBytes the result of the overall computation
	*/
	void firstRound(vector<byte>& outBytes, const vector<byte> & iv, vector<byte> & intermediateOutBytes, int outLength);

public:
	HKDF(const shared_ptr<Hmac> & hmac = make_shared<OpenSSLHMAC>()) { this->hmac = hmac; };

	/**
	* This function derives a new key from the source key material key.
	* The pseudo-code of this function is as follows:
	*
	*   COMPUTE PRK = HMAC(XTS, SKM) [key=XTS, data=SKM]
	*   Let t be the smallest number so that t * |H|>L where |H| is the HMAC output length
	*   K(1) = HMAC(PRK,(CTXinfo,1)) [key=PRK, data=(CTXinfo,1)]
	*   FOR i = 2 TO t
	*     K(i) = HMAC(PRK,(K(i-1),CTXinfo,i)) [key=PRK, data=(K(i-1),CTXinfo,i)]
	*   OUTPUT the first L bits of K(1),�,K(t)
	*
	*   @param iv - CTXInfo
	*
	* Note that this function is thread safe!
	*/
	SecretKey deriveKey(const vector<byte> & entropySource, int inOff, int inLen, int outLen, const vector<byte>& iv = vector<byte>()) override;

};
