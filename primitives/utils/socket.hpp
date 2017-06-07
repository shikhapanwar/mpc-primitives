#pragma once

/*Including boost library and other UDF header files*/
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/system/error_code.hpp>
#include <boost/bind.hpp>
#include <mutex>
#include <thread>
#include <condition_variable>
#include "payload.hpp"   //class definition of message body + header
#include "../headers/exception.hpp" //contains Exception handling + debugging methods and few boost classes

/*rename for easy usage*/
typedef boost::asio::io_service SERVICE;
namespace IP = boost::asio::ip;

/*rename for easy usage*/
using TCP = IP::tcp;
using ADDRESS = IP::address;
using SOCKETSSL = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
using ACCEPTOR = TCP::acceptor;
using SOCKET = TCP::socket;

/*Marker interface for parties implementing socket */
class User{};


// User class that uses TCP sockets
class userSocket : public User{

private: 
	ADDRESS ip;
	int portno;

public:
	//Default constructor
	userSocket(){};

	//parametrized constructor
	userSocket(ADDRESS ip, int portno){

		this->ip=ip;
		this->portno=portno;

	}; //endofconstructor

	//get methods for private members
	ADDRESS getADDRESS(){

		return ip;

	};

	int getPortNo()
	{
		return portno;

	}; 

	//get string output for IP Address and Port No
	string toStringIP()
	{
		return ip.to_string();

	};

	string toStringPort()
	{
		return to_string(portno);

	};

};//endofclass userSocket


/*Class (concrete) for implementing connection defined by socket*/
class socketConnection{
public:

	//method to read the data from the channel into buffer. No of bytes to be read is obtained by sizeToRead param
	//Blocking System call
	virtual size_t readData(byte* buffer, int sizeToRead) = 0;	

	//method to read the incoming data size
	virtual int readDataSize();

	//method to read the data into a vector limited by size
	virtual size_t readBoundedIntoVector(vector<byte> & targetVector);

	//Writing data into other party's channel
	//overloaded methods
	// Blocking system call
	virtual void writeData(const byte* data, int size) = 0;

	virtual void writeData(string s) { 
		
		writeData((const byte *)s.c_str(), s.size()); 

	};

	//write with bounded size requirements at the beginning of write
	//overloaded methods
	virtual void writeBounded(const byte* data, int size);

	virtual void writeBounded(string s) { 
		
		writeBounded((const byte*)s.c_str(), s.size()); 

	};

	//Setup duplex connection and handle connection establishment, blocking system call
	virtual void join(int sleep_between_attempts, int timeout) = 0;

	//destructor
	virtual ~socketConnection();

}; //endofclass socketConnection

/*Class that uses the socketConnection to establish communication */
class userConnection : public socketConnection{

private:
	SERVICE& ioServiceServer;
	SERVICE& ioServiceClient;
	ACCEPTOR acceptor_;
	SOCKET serverSocket;
	SOCKET clientSocket;
	userSocket mysocket;
	userSocket P2socket;
	void SocketOptions();


public:

	//userConnection(){};

	//constructor
	userConnection(SERVICE& ioService, userSocket mysocket, userSocket P2socket) :
		ioServiceServer(ioService), ioServiceClient(ioService),
		acceptor_(ioService, TCP::endpoint(TCP::v4(), mysocket.getPortNo())),
		serverSocket(ioService), clientSocket(ioService)
	{
		this->mysocket = mysocket;
		this->P2socket = P2socket;
	};	

	//Setup duplex connection and handle connection establishment, blocking system call
	void join(int wait = 500, int timeout = 5000) override;

	//Overriding method of super class to write data into the channel
	void writeData(const byte* data, int size) override;

	//Overriding method of super class to read data from the channel
	size_t readData(byte* data, int sizeToRead) override {
			
			//call boost method read to perform read
			return boost::asio::read(serverSocket, boost::asio::buffer(data, sizeToRead));

	}	

	//destructor
	 ~userConnection(){

	 	//close open sockets
	 	acceptor_.close();
		serverSocket.close();
		clientSocket.close();

	 };	

}; //endofclass userConnection


/*Class that implements TCP with SSL Sockets */
class SSLUserConnection : public socketConnection{

private:
	SERVICE& ioServiceServer;
	SERVICE& ioServiceClient;
	ACCEPTOR acceptor_;
	SOCKETSSL* serverSocket;
	SOCKETSSL* clientSocket;
	userSocket mysocket;
	userSocket P2socket;	

public:
	//SSLUserConnection(){};

	//constructor
	SSLUserConnection(SERVICE& ioService, userSocket mysocket, userSocket P2socket,
		string certificateChainFile, string password, string privateKeyFile, string tmpDHFile,
		string clientVerifyFile);

	//Overriding method of super class to read data from the channel
	size_t readData(byte* data, int sizeToRead) override {
		return boost::asio::read(*serverSocket, boost::asio::buffer(data, sizeToRead));
	}

	//Overriding method of super class to write data into the channel
	void writeData(const byte* data, int size) override;

	//Setup duplex connection and handle connection establishment, blocking system call
	void join(int wait = 500, int timeout = 5000) override;

	//Destructor
	~SSLUserConnection(){

		//close all open sockets
		acceptor_.close();
		serverSocket->lowest_layer().close();
		clientSocket->lowest_layer().close();

	};

};
