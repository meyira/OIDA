#include "oprf.h"

using namespace emp;

extern "C" int nr_oprf_c(int socket, const unsigned char *in, size_t in_len, public_key *out)
{
  assert(in_len == 32);
  init_classgroup();
  size_t N = 256;

  NetIO *io = new NetIO(false, socket);
  PQOT ot(io, 2, 1, 17);
  io->sync();
  ot.keygen(); 

  // OPRF
  bool input[N];
  mpz_t m_0[N];

  for(size_t i=0; i<N; ++i){
    input[i] = (in[i / 8] >> (i % 8)) & 1;
    mpz_init(m_0[i]);
  }

  ot.recv_ot(m_0, input, N, sizeof(private_key)*8);

  private_key priv={0};
  mpz_t t; 

  mpz_init(t);
  for(size_t i=0; i<N; ++i){
    mpz_add(t,t,m_0[i]);
      if(input[i]){
        mpz_fdiv_r(t,t,cn);
        mpz_add(t,t,cn);
      }
  }
  mpz_fdiv_r(t,t,cn);
  mpz_add(t,t,cn);
  mod_cn_2_vec(t,priv.e);

  io->recv_data(out, sizeof(public_key));
  csidh(out, out, &priv);

  delete io;
  return 0; 
}

extern "C" void kat(const unsigned char *seed, const unsigned char *hashed_pw, public_key *out) {
  init_classgroup();
  size_t N = 256;
  mpz_t t; 
  mpz_init(t);

  mpz_t mpz_keys[N + 1];
  for(size_t i = 0; i < N + 1; i++){
    mpz_init(mpz_keys[i]); 
  }

  for(size_t i = 0; i < N + 1; i++){
    sample_mod_cn_with_seed(seed+(i*SEED_BYTES), mpz_keys[i]); 
  }

  mpz_add(t,t,mpz_keys[0]);

  for(size_t i=0; i<N; ++i){
    // simulate random input
    if((hashed_pw[i / 8] >> (i % 8)) & 1) {
      mpz_add(t,t,mpz_keys[i+1]);
    }
  }
  private_key priv;
  mpz_fdiv_r(t,t,cn);
  mpz_add(t,t,cn);
  mod_cn_2_vec(t,priv.e);
  csidh(out, &base, &priv);
  mpz_clear(t);
}

extern "C" int nr_oprf_s(int socket, const unsigned char *seed, size_t in_len) {
  assert(in_len == 32);
  init_classgroup();

  // 32 * 8bit
  size_t N = 256;

  mpz_t mpz_keys[N + 1];
  private_key priv_key[N + 1];
  for(size_t i = 0; i < N + 1; i++){
    mpz_init(mpz_keys[i]); 
  }

  for(size_t i = 0; i < N + 1; i++){
    sample_mod_cn_with_seed(seed+(i*SEED_BYTES), mpz_keys[i]); 
    mod_cn_2_vec(mpz_keys[i], priv_key[i].e); 
  }

  NetIO *io = new NetIO(true, socket);
  PQOT ot(io, 1, 1, 17);
  io->sync();
  ot.keygen();

  unsigned char ephem_seed[SEED_BYTES*N]; 
  RAND_bytes(ephem_seed,SEED_BYTES*N);
  mpz_t m_0[N];
  mpz_t m_1[N];
  mpz_t blinder;
  mpz_init(blinder);
  for(size_t i=0; i<N; ++i){
    mpz_inits(m_0[i],m_1[i],NULL); 

    // sample blinder
    sample_mod_cn_with_seed(ephem_seed+(i*SEED_BYTES),m_0[i]); 

    // compute blinded key
    mpz_add(m_1[i],m_0[i],mpz_keys[i+1]);
    mpz_fdiv_r(m_1[i],m_1[i],cn); 
    mpz_add(m_1[i],m_1[i],cn); 
    mpz_sub(blinder, blinder, m_0[i]);

  }

  ot.send_ot(m_0, m_1, N, sizeof(private_key)*8);

  private_key priv = {0};
  mpz_add(blinder, blinder, mpz_keys[0]);
  mpz_fdiv_r(blinder,blinder,cn);
  mpz_add(blinder,blinder,cn);
  mod_cn_2_vec(blinder,priv.e);
  public_key result;
  csidh(&result, &base, &priv);
  io->send_data(&result, sizeof(public_key));
  mpz_clear(blinder);

  delete io;
  return 0; 
}
