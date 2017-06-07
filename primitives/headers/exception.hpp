#pragma once

#include <iostream>
#include <fstream>




using namespace std;

class IllegalStateException : public logic_error
{
public:
	IllegalStateException(const string & msg) : logic_error(msg) {};
};

class NotImplementedException : public logic_error
{
public:
	NotImplementedException(const string & msg) : logic_error(msg) {};
};

class InvalidKeyException : public logic_error
{
public:
	InvalidKeyException(const string & msg) : logic_error(msg) {};
};

class KeyException : public logic_error
{
public:
	KeyException(const string & msg) : logic_error(msg) {};
};

class UnsupportedOperationException : public logic_error
{
public:
	UnsupportedOperationException(const string & msg) : logic_error(msg) {};
};

class SecurityLevelException : public logic_error
{
public:
	SecurityLevelException(const string & msg) : logic_error(msg) {};
};

class CheatAttemptException : public logic_error
{
public:
	CheatAttemptException(const string & msg) : logic_error(msg) {};
};

class TimeoutException : public logic_error
{
public:
	TimeoutException(const string & msg) : logic_error(msg) {};
};

class DuplicatePartyException : public logic_error
{
public:
	DuplicatePartyException(const string & msg) : logic_error(msg) {};
};

class PartyCommunicationException : public logic_error
{
public:
	PartyCommunicationException(const string & msg) : logic_error(msg) {};
};




