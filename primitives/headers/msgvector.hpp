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
* MPC-PRIMITIVES uses several open source libraries. Please see these projects for any further licensing issues.cal
* For more information , See https://raw.githubusercontent.com/cris-iisc/mpc-primitives/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/

#ifndef MSGVECTOR_H
#define MSGVECTOR_H
#include "common.hpp"
#include <math.h>

//Some constants neede, can be shifted together to create 'typedefs.hpp' if needed
#define MSG_BLOCK_BITS	128
#define MSG_BLOCK_BYTE 16

#define getIntBitsFromLen(x, from, len) 	( ( (x & ( ( (2<<(len))-1) << from )) >> from) & 0xFF)
#define getMask(len) 				(( (1<<(len))-1))

static const byte MASK_BIT[8] =
{ 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 };

static const byte BIT[8] =
{ 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80 };
//compliment of BIT
static const byte C_BIT[8] =
	{ 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f };

static const byte CMASK_BIT[8] =
{ 0x7f, 0xbf, 0xdf, 0xef, 0xf7, 0xfb, 0xfd, 0xfe };

static const byte MASK_SET_BIT_C[2][8] =
{ {0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1},{0,0,0,0,0,0,0,0} };


static const byte SET_BIT_C[2][8] =
{ {0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80},{0,0,0,0,0,0,0,0} };

//class similar to cbitvector, abstracts message block in a nice way
class MsgVector{
	private:
		byte *msg_ptr;
		int msg_size;
		int msg_bit_size;

	public:
		//default constructor
		MsgVector(){
			create();
		}
		MsgVector(int bits){
			create(bits);
		}
		~MsgVector(){
			delMsgVector();
		}
		void delMsgVector() {
			if (( msg_size > 0 )&& (msg_ptr != NULL)) {
				free(msg_ptr);
			}
			msg_size = 0;
			msg_ptr = NULL;
		}
		//overloaded create functions
		//default initialization setting size to 0 and ptr to NULL
		void create(){
			msg_ptr = NULL;
			msg_size = 0;
		}
		void create(int bits);

		//TODO: void create(int bits, randomness) initialize random bits

		void createBytes(int bytes){
			create(bytes<<3);
		}
		void createZeros(int bits){
			create(bits);
			memset(msg_ptr,0,msg_size);
		}

		/*
		 * Management operations *
		 */
		void reset() {
			memset(msg_ptr, 0, msg_size);
		}
		void resetFromTo(int frombyte, int tobyte) {
			assert(frombyte >= tobyte);
			assert(tobyte > msg_size);
			memset(msg_ptr+frombyte, 0x00, tobyte-frombyte);
		}
		void setToOne() {
			memset(msg_ptr, 0xff, msg_size);
		}
		int getSize(){
			return msg_size;
		}
		byte* getArray(){
			return msg_ptr;
		}
		void resizeinBytes(int newsize);
		bool isEqual(MsgVector& vec);
		bool isEqual(MsgVector& vec, int from, int to);
		void invert();


		/*
		 * Copy operations *
		 */
		void copy(MsgVector& vec){
			copy(vec.getArray(), 0, vec.getSize());
		}
		void copy(MsgVector& vec, int pos, int len){
			copy(vec.getArray(), pos, len);
		}
		void copy(byte* p, int pos, int len);


		//not requerd I guess; implement only if required.
		//void XOR_no_mask(int p, int bitPos, int bitLen);
		//unsigned int GetInt(int bitPos, int bitLen);

		
		/*
		 * Bitwise operations
		 */
		byte getBit(int idx){
			return !!(msg_ptr[idx >> 3] & MASK_BIT[idx & 0x7]);
		}
		void setBit(int idx, byte b){
			msg_ptr[idx >> 3] = (msg_ptr[idx >> 3] & CMASK_BIT[idx & 0x7]) | MASK_SET_BIT_C[!b][idx & 0x7];
		}
		void xorBit(int idx, byte b){
			msg_ptr[idx >> 3] ^= MASK_SET_BIT_C[!b][idx & 0x7];
		}
		void andBit(int idx, byte b){
			if (!b) msg_ptr[idx >> 3] &= CMASK_BIT[idx & 0x7];
		}
		
		//used to access bits in the regular order
		byte getBitNoMask(int idx){
			return !!(msg_ptr[idx >> 3] & BIT[idx & 0x7]);
		}
		void setBitNoMask(int idx, byte b){
			msg_ptr[idx >> 3] = (msg_ptr[idx >> 3] & C_BIT[idx & 0x7]) | SET_BIT_C[!b][idx & 0x7];
		}
		void xorBitNoMask(int idx, byte b){
			msg_ptr[idx >> 3] ^= SET_BIT_C[!b][idx & 0x7];
		}
		void andBitNoMask(int idx, byte b){
			if (!b) msg_ptr[idx >> 3] &= C_BIT[idx & 0x7];
		}


		/*
		 * Single byte operations
		 */
		void setByte(int idx, byte p) {
			msg_ptr[idx] = p;
		}
		byte getByte(int idx){
			return msg_ptr[idx];
		}
		void xorByte(int idx, byte b){
			msg_ptr[idx] ^= b;
		}
		void andByte(int idx, byte b){
			msg_ptr[idx] &= b;
		}
		void orByte(int pos, byte p){
			msg_ptr[pos] |=p;
		}

		/*
		 * Get Operations TODO
		 */
		//void getBits(byte* p, int pos, int len);
		//void getBytes(byte* p, int pos, int len);
		//template <class T> void getBytes(T* dst, T* src, T* lim);
		/*template <class T> T get(int pos, int len){
			T val = 0;
			getBits((byte*)&val, pos, len);
			return val;
		}*/

		/*
		 * Set Operations
		 */
		/*
		void setBits(byte* p, int pos, int len);
		void setBytes(byte* p, int pos, int len);
		template <class T> void setBytes(T* dst, T* src, T* lim);
		template <class T> void set(T val, int pos, int len){
			setBits((byte*)&val, pos, len);
		}
		*/
		void setBitsToZero(int bitpos, int bitlen);

		//Print functions
		//todo: printBinaryMasked and printContent
		void print(int fromBit, int toBit);
		void printHex();
		void printHex(int fromByte, int toByte);
		void printBinary() { print(0, msg_size<<3); }
		void printContent();
		void printBinaryMasked(int from, int to);
};

#endif //MSGVECTOR_H