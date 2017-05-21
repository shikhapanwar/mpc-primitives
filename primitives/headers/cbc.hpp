#include "prf.hpp"

class MacPRF : public PrfWithFixedLen{

protected:
	shared_ptr<PrfwithFixedLen> prfFixed; //the underlying prf.

public:

	virtual void computePRFBlock(const vector<byte> & inBytes, int inOffset, vector<byte> &outBytes, int outOffset);

	bool isKeyDefined() override { 

		return prfFixed->isKeyDefined();

	 };

	 void setPRFKey(SecretKey & secretKey) override { 
	 	
	 	prfFixed->setPRFKey(secretKey); 

	 };

};

class CBCMac : public UniqueTagMac{

protected:
	shared_ptr<MacPRF> macprf;

public:
	bool _isKeyDefined;  // Until setPRFKey is called set to false.

	bool isKeyDefined() override { 
		
		return _isKeyDefined; 
		
	};

	string getAlgorithmName() override;	



};