#include <iostream>
#include <chrono>
#include <cstring>
#include <opus-psi/SecureRandom.h>

using namespace OpusPsi;
int main(int argc, char** argv) {

  size_t num_inputs = 1ULL << 2;
  //client
  //  SSINRPSIClientLattice client(argv[1], port);

  // SSINRPSIClient client(chan);
  SecureRandom rnd;
  std::vector<block> elements; 
  // get one good result to test intersection
  for(size_t i = 0; i < num_inputs; i++) {
    elements.push_back(rnd.randBlock());
  }
  for(size_t i = 0; i < num_inputs; i++) {
    uint64_t out[2];
    out[0]=(uint64_t)elements[i][0];
    out[1]=(uint64_t)elements[i][1];
  std::cout<<out[0]<<out[1]<<std::endl; 
  }
  return 0;
}


