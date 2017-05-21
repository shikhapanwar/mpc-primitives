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