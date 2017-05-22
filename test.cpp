#include<iostream>
#include "primitives/headers/prg.hpp"
#include "primitives/headers/hash.hpp"
#include "primitives/headers/sampleprf.hpp"


using namespace std;
int main(){
	PrgFromAES aess(10,true);
	Hash sha512("SHA512");
	OpenSSLTripleDES prs;

	cout<<"hello cris\n";
	
}
