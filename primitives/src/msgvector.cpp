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

#include "../headers/msgvector.hpp"

int ceilDivide(int a, int b){
	return (1 + (a-1)/b);
}
/*Create Overloaded functions*/
	void MsgVector::create(int bits){
		if (bits == 0)
			bits = MSG_BLOCK_BITS;

		int size = ceilDivide( bits, MSG_BLOCK_BITS );

		if (msg_size>0)	free(msg_ptr);
		msg_size = size*MSG_BLOCK_BYTE;
		msg_bit_size = bits;
		msg_ptr = (byte*) calloc(msg_size,sizeof(byte));
		assert(msg_ptr != NULL);
	}
 

/* Manage functions implementations*/
void MsgVector::resizeinBytes(int newsize)
{
	//Why not realloc
	//TODO: check that
	byte* t_ptr = msg_ptr;
	int t_size = msg_size;

	msg_size = newsize;
	msg_ptr = (byte*)malloc(sizeof(byte) * msg_size);
	if (msg_ptr == NULL)
	{
		cerr << "Memory allocation failed in CBitVector, requested size: " <<
			msg_size << " bytes" << endl;
		exit(0);
	}

	memcpy(msg_ptr, t_ptr, t_size);

	free(t_ptr);
}
bool MsgVector::isEqual(MsgVector& vec){
	if(msg_size != vec.getSize()){
		return false;
	}
	byte *msg = vec.getArray();
	for(int i=0;i<msg_size;i++){
		if(msg_ptr[i] != msg[i])
			return false;
	}
	return true;
}

bool MsgVector::isEqual(MsgVector& vec, int from, int to){
	if(vec.getSize() * 8 < to || msg_size * 8 < to || from > to){
		return false;
	}
	for(int i=from;i<to;i++){
		if(vec.getBit(i)!=getBit(i))
			return false;
	}
	return true;
}
void MsgVector::invert(){
	for(int i=0;i<msg_size;i++){
		msg_ptr[i] = ~msg_ptr[i];
	}
}


/*Copy functions*/
	void MsgVector::copy(byte* p, int pos, int len){
		if (pos + len > msg_size)
		{
			if (msg_ptr)
				resizeinBytes(pos + len);
			else
				createBytes(pos + len);
		}
		memcpy(msg_ptr + pos, p, len);
	}

void MsgVector::setBitsToZero(int bitpos, int bitlen){
	int firstlim = ceilDivide(bitpos, 8);
	int firstlen = ceilDivide(bitlen - (bitpos % 8), 8);
	for (int i = bitpos; i < firstlim; i++)
	{
		setBitNoMask(i, 0);
	}
	if (bitlen > 7)
	{
		memset(msg_ptr + firstlim, 0, firstlen);
	}
	for (int i = (firstlim + firstlen) << 8; i < bitpos + bitlen; i++)
	{
		setBitNoMask(i, 0);
	}
}


/*PRINT METHODS*/
	/*print from index fromBit to index toBit*/
	void MsgVector::print(int fromBit, int toBit){
		if (toBit>(msg_size << 3))
			cout<< "Not in range"<<endl;
		else
		{
			for (int i = fromBit; i < toBit; i++)
				cout << (unsigned int) getBitNoMask(i);
			cout << endl;
		}
	}

	void MsgVector::printHex(){
		for(int i=0;i<msg_size;i++)
			cout << setw(2) << setfill('0') << (hex) << ((unsigned int) msg_ptr[i]);
		cout<<endl;
	}

	void MsgVector::printHex(int fromByte, int toByte){
		if(toByte>msg_size)
			cout<<"Not in range"<<endl;
		else
		{
			for (int i = fromByte; i < toByte; i++)
				cout << setw(2) << setfill('0') << (hex) << ((unsigned int) msg_ptr[i]);
			cout << endl;
		}
	}

	void MsgVector::printContent(){

	}

	void MsgVector::printBinaryMasked(int from, int to){

	}