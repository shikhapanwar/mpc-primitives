#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/system/error_code.hpp>
#include <boost/bind.hpp>
#include <mutex>
#include <thread>
#include <condition_variable>
#include "payload.hpp"   //class definition of message body + header
#include "../headers/common.hpp" //contains Exception handling + debugging methods and few boost classes

namespace boost_ip = boost::asio::ip; // reduce the typing a bit later...
using IpAddress = boost_ip::address;
using tcp = boost_ip::tcp;


/**
* A marker interface. Each type of party should have a concrete class that implement this interface.
*/
class PartyData{};

/**
* This class holds the data of a party in a communication layer.
* It should be used in case the user wants to use the regular mechanism of communication using tcp sockets.
*/
class SocketPartyData : public PartyData {
private:
	IpAddress ipAddress; // party's address.
	int port; // port number to listen on.
	int compare(const SocketPartyData &other) const;
public:
	SocketPartyData() {};
	/**
	* Constructor that sets the given arguments.
	* @param ip Party's address.
	* @param port Port number to listen on.
	*/
	SocketPartyData(IpAddress ip, int port) {
		ipAddress = ip;
		this->port = port;
	};
	IpAddress getIpAddress() { return ipAddress; };
	int getPort() { return port; };
	string to_log_string() {
		return ipAddress.to_string() + "|" + to_string(port);
	};
	/**
	* Compares two parties.
	*<0 if this party's string is smaller than the otherParty's string representation.
	*>0 if this party's string is larger than the otherParty's string representation.
	*/
	bool operator==(const SocketPartyData &other) const { return (compare(other) == 0); };
	bool operator!=(const SocketPartyData &other) const { return (compare(other) != 0); };
	bool operator<=(const SocketPartyData &other) const { return (compare(other) <= 0); };
	bool operator>=(const SocketPartyData &other) const { return (compare(other) >= 0); };
	bool operator>(const SocketPartyData &other) const { return (compare(other) > 0); };
	bool operator<(const SocketPartyData &other) const { return (compare(other) < 0); };
};

/**
* A simple interface that encapsulate all network operations of one peer in a two peers (or more)
* setup.
*/
class CommParty {
public:

	CommParty(){}
	/**
	* This method setups a double edge connection with another party.
	* It connects to the other party, and also accepts connections from it.
	* The method blocks until boths side are connected to each other.
	*/
	virtual void join(int sleep_between_attempts, int timeout) = 0;
	/**
	* Write data from @param data to the other party.
	* Will write exactly @param size bytes
	*/
	virtual void write(const byte* data, int size) = 0;
	/**
	* Read exactly @param sizeToRead bytes int @param buffer
	* Will block until all bytes are read.
	*/
	virtual size_t read(byte* buffer, int sizeToRead) = 0;
	virtual void write(string s) { write((const byte *)s.c_str(), s.size()); };
	virtual void writeWithSize(const byte* data, int size);
	virtual int readSize();
	virtual size_t readWithSizeIntoVector(vector<byte> & targetVector);
	virtual void writeWithSize(string s) { writeWithSize((const byte*)s.c_str(), s.size()); };
	virtual ~CommParty(){};
};

class CommPartyTCPSynced : public CommParty {
public:
	CommPartyTCPSynced(boost::asio::io_service& ioService, SocketPartyData me, SocketPartyData other) :
		ioServiceServer(ioService), ioServiceClient(ioService),
		acceptor_(ioService, tcp::endpoint(tcp::v4(), me.getPort())),
		serverSocket(ioService), clientSocket(ioService)
	{
		this->me = me;
		this->other = other;
	};
	void join(int sleepBetweenAttempts = 500, int timeout = 5000) override;

	void write(const byte* data, int size) override;
	size_t read(byte* data, int sizeToRead) override {
		return boost::asio::read(serverSocket, boost::asio::buffer(data, sizeToRead));
	}
	 ~CommPartyTCPSynced(){
		 acceptor_.close();
		serverSocket.close();
		clientSocket.close();
	}; 

private:
	boost::asio::io_service& ioServiceServer;
	boost::asio::io_service& ioServiceClient;
	tcp::acceptor acceptor_;
	tcp::socket serverSocket;
	tcp::socket clientSocket;
	SocketPartyData me;
	SocketPartyData other;
	void setSocketOptions();
};

typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;

class CommPartyTcpSslSynced : public CommParty {
public:
	CommPartyTcpSslSynced(boost::asio::io_service& ioService, SocketPartyData me, SocketPartyData other,
		string certificateChainFile, string password, string privateKeyFile, string tmpDHFile,
		string clientVerifyFile);
	void join(int sleepBetweenAttempts = 500, int timeout = 5000) override;
	void write(const byte* data, int size) override;
	size_t read(byte* data, int sizeToRead) override {
		return boost::asio::read(*serverSocket, boost::asio::buffer(data, sizeToRead));
	}
	virtual ~CommPartyTcpSslSynced();

private:
	boost::asio::io_service& ioServiceServer;
	boost::asio::io_service& ioServiceClient;
	tcp::acceptor acceptor_;
	ssl_socket* serverSocket;
	ssl_socket* clientSocket;
	SocketPartyData me;
	SocketPartyData other;
};

