#include "socket.hpp"

/*Methods of socketConnection class */
//method to obtain the size of the data read from the channel
int socketConnection::readDataSize() {
	
	byte buf[sizeof(int)];

	//obtain the data in buf
	readData(buf, sizeof(int));
	
	//extract the size of data read
	int * res = (int *)buf;
	
	return *res;

}//endofmethod


//method to read data into a vector limited by size
size_t socketConnection::readBoundedIntoVector(vector<byte> & targetVector) {
	
	//read the data size
	int msgSize = readDataSize();

	//resize the vector to the desired size
	targetVector.resize(msgSize);

	//read the data into target vector. No of bytes to be read is given by msgSize param
	auto res = readData((byte*)&targetVector[0], msgSize);
	return res;

}//endofmethod

//method to write data with size
void socketConnection::writeBounded(const byte* data, int size) {
	
	//write the size of the data to be written at the start
	writeData((const byte *)&size, sizeof(int));

	//write the message into the channel
	writeData(data, size);

}//endofclass


/*Methods of userConnection class */
//method to write data into the channel. No of bytes to be written is specified by size param
void userConnection::writeData(const byte* data, int size) {
	
	//declare error code
	boost::system::error_code ec; 

	//write into channel and get status of bytes transferred into ec
	boost::asio::write(clientSocket,boost::asio::buffer(data, size),boost::asio::transfer_all(), ec);

	//if error occured then inform the party
	if (ec)
		throw PartyCommunicationException("Error while writing. " + ec.message());

}//endofmethod

/*void userConnection::SocketOptions() {

	boost::asio::ip::tcp::no_delay option(true);
	serverSocket.set_option(option);
	clientSocket.set_option(option);

}*/

//Setup duplex connection and handle connection establishment, blocking system call
void userConnection::join(int wait, int timeout) {
	int     totalSleep = 0;
	bool    isAccepted  = false;
	bool    isConnected = false;

	// establish connections
	while (!isConnected || !isAccepted) {
		try {
			if (!isConnected) {
				//establish TCP connection
				TCP::resolver resolver(ioServiceClient);
				TCP::resolver::query query(P2socket.toStringIP(), P2socket.toStringPort());
				TCP::resolver::iterator endpointIterator = resolver.resolve(query);
				boost::asio::connect(clientSocket, endpointIterator);
				//set var to true
				isConnected = true;
			}
		}
		catch (const boost::system::system_error& ex)
		{
			//check if sleep time is greater than timeout
			if (totalSleep > timeout)
			{
				cerr << "Failed to connect after timeout, aborting!";
				throw ex;
			}
			cout << "Failed to connect. sleeping for " << wait << " milliseconds, " << ex.what() << endl;
			//sleep with timer
			this_thread::sleep_for(chrono::milliseconds(wait));
			//increment sleep time
			totalSleep += wait;
		}
		//if connected but not accepted
		if (!isAccepted) {
			boost::system::error_code ec;
			//call acceptor to accept connection
			acceptor_.accept(serverSocket, ec);
			//set var to true
			isAccepted = true;
		}
	}
	//SocketOptions(); //negotiate options

}//endofmethod

/*userConnection :: ~userConnection() {
	
	acceptor_.close();
	serverSocket.close();
	clientSocket.close();

}*/

/*Methods of SSLUserConnection class */
//Constructor
SSLUserConnection::SSLUserConnection(SERVICE& ioService, userSocket mysocket, 
	userSocket P2socket, string certificateChainFile, string password, string privateKeyFile, 
	string tmpDHFile, string clientVerifyFile) : ioServiceServer(ioService), ioServiceClient(ioService),
	acceptor_(ioService, TCP::endpoint(TCP::v4(), mysocket.getPortNo()))
{
	this->mysocket = mysocket; //my socket
	this->P2socket = P2socket; //other party's socket
	
	// create server SSL context and socket
	boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
	//ctx.set_verify_mode(boost::asio::ssl::verify_none);
	//set options for ssl communication
	ctx.set_options(
		boost::asio::ssl::context::default_workarounds
		| boost::asio::ssl::context::no_sslv2
		| boost::asio::ssl::context::single_dh_use);

	ctx.set_password_callback([password](std::size_t max_length, 
		boost::asio::ssl::context::password_purpose purpose) {return password; });
	ctx.use_certificate_chain_file(certificateChainFile);
	ctx.use_private_key_file(privateKeyFile, boost::asio::ssl::context::pem);
	ctx.use_tmp_dh_file(tmpDHFile);
	serverSocket = new SOCKETSSL(ioService, ctx);
	
	// create client SSL context and socket
	boost::asio::ssl::context clientCtx(boost::asio::ssl::context::sslv23);
	clientCtx.load_verify_file(clientVerifyFile);
	clientSocket = new SOCKETSSL(ioService, clientCtx);

};

//method to write data into the channel
void SSLUserConnection::writeData(const byte* data, int size) {
	
	//declare error code
	boost::system::error_code ec;

	//write into channel and get status of bytes transferred into ec
	boost::asio::write(*clientSocket,boost::asio::buffer(data, size),boost::asio::transfer_all(), ec);

	//if error occured then inform the party
	if (ec)
		throw PartyCommunicationException("Error while writing. " + ec.message());

}//endofmethod

void SSLUserConnection::join(int wait, int timeout) {
	int     totalSleep = 0;
	bool    isAccepted = false;
	bool    isConnected = false;

	// establish connections
	while (!isConnected || !isAccepted) {
		try {
			//establish TCP connection
			if (!isConnected) {
				TCP::resolver resolver(ioServiceClient);
				TCP::resolver::query query(P2socket.toStringIP(), P2socket.toStringPort());
				TCP::resolver::iterator endpointIterator = resolver.resolve(query);
				boost::asio::connect(clientSocket->lowest_layer(), endpointIterator);
				//HandshakeSSL
				clientSocket->handshake(boost::asio::ssl::stream_base::client);
				isConnected = true;
			}
		}
		catch (const boost::system::system_error& ex)
		{
			//if sleep time is more than timeout
			if (totalSleep > timeout)
			{
				cerr << "Failed to connect after timeout, aboting!";
				throw ex;
			}
			cout << "Failed to connect. sleeping for " << wait << " milliseconds, " << ex.what() << endl;
			//sleep with timer
			this_thread::sleep_for(chrono::milliseconds(wait));
			//inc total slept time
			totalSleep += wait;
			
		}//endoftrycatch

		//if connected but not accepted
		if (!isAccepted) {
			boost::system::error_code ec;
			TCP::endpoint peer_endpoint;
			//accept connection
			acceptor_.accept(serverSocket->lowest_layer(), peer_endpoint);

			//handshake
			serverSocket->handshake(boost::asio::ssl::stream_base::server, ec);

			//if error in handshake
			if(ec)
				throw PartyCommunicationException("Handshake failed. " + ec.message());

			//set var to true
			isAccepted = true;
		}//endif

	}//endofwhile

}//endofmethod

/*SSLUserConnection::~SSLUserConnection() {
	
	acceptor_.close();
	serverSocket->lowest_layer().close();
	clientSocket->lowest_layer().close();

}*/


