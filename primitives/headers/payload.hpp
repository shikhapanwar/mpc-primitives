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


#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>

class Data{

public:
	enum e1{hlen = 8};
	enum e2{datalenmax = 3000000};

private:
	int vector_size = hlen + datalenmax;
	size_t datalen;
	std::vector<char> messageData;

public:
	Data(): datalen(0), messageData(hlen + datalenmax)
	{};

	const char* getData() const
	{
		return &(messageData[0]);

	}

	char* getData()
	{
		return &(messageData[0]);

	}

	size_t totLen() const
	{
		return hlen + datalen;

	}	

	const char* messageBody() const
	{
		return &messageData[0] + hlen;

	}

	char* messageBody()
	{
		return &messageData[hlen];

	}

	void dataLength(size_t length)
	{
		datalen = length;
		if (datalen > datalenmax)
			datalen = datalenmax;

	}


	void buildHeader()
	{
		using namespace std; // For sprintf and memcpy.
		char header[hlen + 1] = "";
		sprintf(header, "%4d", (int) datalen);
		memcpy(&messageData[0], header, hlen);
		
	}


	bool extractHeader()
	{
		using namespace std; // For strncat and atoi.
		char header[hlen + 1] = "";
		strncat(header, &messageData[0], hlen);
		datalen = atoi(header);
		if (datalen > datalenmax)
		{
			datalen = 0;
			return false;
		}
		return true;

	}


};