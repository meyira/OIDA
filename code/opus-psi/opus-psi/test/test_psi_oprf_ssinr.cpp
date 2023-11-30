
#include <iostream>
#include <cstring>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/SecureRandom.h>
#include <droidCrypto/psi/SSI/SSINRPSIClientLattice.h>
#include <droidCrypto/psi/SSI/SSINRPSIServerLattice.h>
#include "droidCrypto/utils/Log.h"

int main(int argc, char** argv) {
  std::string ip="127.0.0.1"; 

  if(argc != 3) {
    std::cout << "usage: " << argv[0] << " {role=0,1} {log2(num_inputs)}" << std::endl;
    return -1;
  }
  int exp = std::stoi(std::string(argv[2]));
  if(0 > exp || exp > 32) {
    std::cout << "log2(num_inputs) should be between 0 and 32" << std::endl;
    return -1;
  }
  size_t num_inputs = 1ULL << exp;
  if(strcmp("0", argv[1]) == 0) {
    //server
    std::cout<<"start server"<<std::endl; 

    droidCrypto::SSINRPSIServerLattice server(ip, 8000, 1);
    droidCrypto::SecureRandom rnd;
    std::vector<droidCrypto::block> elements = rnd.randBlocks(num_inputs); 
    // get one good result to test intersection
    elements[0]=(droidCrypto::toBlock((const uint8_t*)"ffffffff88888888"));
    server.Setup(elements);
    std::cout<<"Server setup done"<<std::endl; 
    server.Base(); 
    std::cout<<"Base Phase done"<<std::endl; 
    server.Online(); 
  }
  else if(strcmp("1", argv[1]) == 0) {
    //client
    droidCrypto::SSINRPSIClientLattice client(ip, 8000);

    // droidCrypto::SSINRPSIClient client(chan);
    droidCrypto::SecureRandom rnd;
    std::vector<droidCrypto::block> elements = rnd.randBlocks(num_inputs); 
    // get one good result to test intersection
    elements[1]=(droidCrypto::toBlock((const uint8_t*)"ffffffff88888888"));

    client.Setup(); 
    std::cout<<"client setup done"<<std::endl; 
    client.Base(num_inputs); 
    std::cout<<"Base Phase done"<<std::endl; 
    std::vector<size_t> res=client.Online(elements); 
  }
  else {
    std::cout << "usage: " << argv[0] << " {0,1}" << std::endl;
    return -1;
  }
  return 0;
}
