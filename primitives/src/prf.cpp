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


#include "../headers/prf.hpp"



void PrpFromPrfFixed::computePRFBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte>& outBytes, int outOffset, int outLen) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	if ((inOffset > (int)inBytes.size()) || (inOffset + inLen > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOffset > (int)outBytes.size()) || (outOffset + outLen > (int)outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	// If the input and output length are equal to the blockSize, call the computeBlock that doesn't take length arguments.
	if (inLen == outLen && inLen == getPRFBlockSize())
		computePRFBlock(inBytes, inOffset, outBytes, outOffset);
	else
		throw out_of_range("input and output lengths should be equal to Block size");

}

void PrpFromPrfFixed::computePRFBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte>& outBytes, int outOffset) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	if ((inOffset > (int)inBytes.size()) || (inOffset + inLen > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOffset > (int)outBytes.size()) || (outOffset + getPRFBlockSize() > (int)outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	// if the input and output length are equal to the blockSize, call the computeBlock that doesn't take length arguments.
	if (inLen == getPRFBlockSize())
		this->computePRFBlock(inBytes, inOffset, outBytes, outOffset);
	else
		throw out_of_range("input and output lengths should be equal to Block size");

}

void PrpFromPrfFixed::invertBlock(const vector<byte> & inBytes, int inOffset, vector<byte>& outBytes, int outOffset, int len) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	// Checks that the offset and length are correct 
	if ((inOffset > (int)inBytes.size()) || (inOffset + len > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOffset > (int)outBytes.size()) || (outOffset + len > (int)outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");
	if (len == getPRFBlockSize()) //the length is correct
		//Call the derived class implementation of invertBlock ignoring len
		invertBlock(inBytes, inOffset, outBytes, outOffset);
	else
		throw out_of_range("the length should be the same as block size");

}

void IteratedPrfVarying::computePRFBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> & outBytes, int outOffset, int outLen) {
	if (!isKeyDefined())
		throw invalid_argument("secret key isn't set");
	
	// Checks that the offset and length are correct 
	if ((inOffset > (int)inBytes.size()) || (inOffset + inLen >(int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOffset > (int)outBytes.size()) || (outOffset + outLen >(int)outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	int prfLength = prfVaryingInputLength->getPRFBlockSize(); // The output size of the prfVaryingInputLength.
	int rounds = (int) ceil((float)outLen / (float)prfLength);  // The smallest integer for which rounds * prfLength > outlen.
	vector<byte> intermediateOutBytes(prfLength); // Round result
	vector<byte> currentInBytes(inBytes.begin() + inOffset, inBytes.begin() + inOffset + inLen); 	//Copy the x (inBytes) to the input of the prf in the beginning.
	currentInBytes.push_back((byte)outLen); // Works for len up to 256. Copy the outLen to the input of the prf after the x.

	int bulk_size;
	int start_index;

	for (int i = 1; i <= rounds; i++) {
		
		currentInBytes.push_back((byte)i); // Works for len up to 256. Copy the i to the input of the prf.
		// operates the computeBlock of the prf to get the round output
		prfVaryingInputLength->computePRFBlock(currentInBytes, 0, inLen + 2, intermediateOutBytes, 0);
		// copies the round result to the output byte array
		start_index = outOffset + (i - 1)*prfLength;
		// in case of the last round - copies only the number of bytes left to match outLen
		bulk_size = (i == rounds) ? outLen - ((i - 1)*prfLength) : prfLength; 
		memcpy(outBytes.data() + start_index, intermediateOutBytes.data(), bulk_size);
	}

}



void PrpFromPrfVarying::computePRFBlock(const vector<byte> & inBytes, int inOffset, vector<byte>& outBytes, int outOffset) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	throw out_of_range("to use this prp, call the computeBlock function that specifies the block size length");

}

void PrpFromPrfVarying::computePRFBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte>& outBytes, int outOffset, int outLen) {
	
	if (!isKeyDefined())
		throw new IllegalStateException("secret key isn't set");
	// Check that the offsets and lengths are correct.
	if ((inOffset > (int)inBytes.size()) || (inOffset + inLen > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOffset > (int)outBytes.size()) || (outOffset + outLen > (int)outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	//If the input and output lengths are equal, call the computeBlock which takes just one length argument.
	if (inLen == outLen)
		computePRFBlock(inBytes, inOffset, inLen, outBytes, outOffset);

	else throw out_of_range("input and output lengths should be equal");

}

void PrpFromPrfVarying::invertBlock(const vector<byte> & inBytes, int inOffset, vector<byte>& outBytes, int outOffset) {
	
	if (!isKeyDefined())
		throw IllegalStateException("secret key isn't set");
	throw out_of_range("to use this prp, call the invertBlock function which specify the block size length");

}
