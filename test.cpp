#include<iostream>
#include "primitives/utils/socket.hpp"
 #include "primitives/headers/configfile.hpp"
 #include "primitives/headers/prg.hpp"
// #include "primitives/headers/hash.hpp"
// #include "primitives/headers/sampleprf.hpp"


void testSocket()
{
  int numParties = 10;

  //open file
  ConfigFile cf("Parties");

  string portString, ipString;
  vector<int> ports(numParties);
  vector<string> ips(numParties);
  int counter = 0;
  for (int i = 0; i < numParties; i++) {
      portString = "party_" + to_string(i) + "_port";
      ipString = "party_" + to_string(i) + "_ip";
      //get partys IPs and ports data
      ports[i] = stoi(cf.Value("", portString));
      ips[i] = cf.Value("", ipString);
  }

  SERVICE io_service;

  int id =3;
  for (int i=0; i<numParties; i++){
      if (i < id) {// This party will be the receiver in the protocol
        userSocket me(ADDRESS::from_string(ips[id]), ports[id] + i);
        cout<<"my port = "<<ports[id] + i<<endl;
        userSocket other(ADDRESS::from_string(ips[i]), ports[i] + id - 1);
        cout<<"other port = "<<ports[i] + id - 1<<endl;
        cout<<me.getADDRESS()<<" "<<me.getPortNo()<<endl;
        cout<<other.getADDRESS()<<" "<<other.getPortNo()<<endl;
        shared_ptr<socketConnection> channel = make_shared<userConnection>(io_service, me, other);        // connect to party one
        channel->join(500, 5000);
        cout<<"channel established"<<endl;

      } else if (i>id) {// This party will be the sender in the protocol
          userSocket me(ADDRESS::from_string(ips[id]), ports[id] + i-1);
          cout<<"my port = "<<ports[id] + i -1 <<endl;
          userSocket other(ADDRESS::from_string(ips[i]), ports[i] + id);
          cout<<"other port = "<< ports[i] + id<<endl;
        shared_ptr<socketConnection> channel = make_shared<userConnection>(io_service, me, other);
          // connect to party one
          channel->join(500, 5000);
          cout<<"channel established"<<endl;
      }
  }
}

int main(){
		testSocket();
	}
