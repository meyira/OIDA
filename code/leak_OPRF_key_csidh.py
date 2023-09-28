#/usr/bin/python3
from random import randrange
import numpy as np
from time import sleep
MAX_EXPONENT=5
NUM_PRIMES=74
def gen_key():
  # generate random key
  kee=[]
  for i in range(NUM_PRIMES): 
    kee.append(randrange(-MAX_EXPONENT, MAX_EXPONENT+1))
  return kee

def blind_key(private_key, random):
    blinded=[]
    for j in range(NUM_PRIMES): 
      # blind
      blinded.append(random[j]+private_key[j])
    return blinded

if __name__=="__main__": 
  found=0
  found_min=10000
  found_max=0
  for _ in range(1): 
    # average over 100 runs
    private_key=gen_key()
    guessed_key=[0]*NUM_PRIMES
    known=[0]*NUM_PRIMES
    intermediate_keys=[]
    # try 1000 times, usually succeeds after ~50
    for i in range(1000): 
      sleep(0.7)
      # random blinding key
      random=gen_key()
      # blind
      blinded=blind_key(private_key, random)
      intermediate_keys.append(blinded)
      nparr=np.array(intermediate_keys)
      for j in range(NUM_PRIMES): 
        if known[j]==0: 
          # try to estimate
          arr=nparr[:,j]
          if 10 in arr: 
            guessed_key[j]=5
            known[j]=1
          if -10 in arr: 
            guessed_key[j]=-5
            known[j]=1
          distance=np.amax(nparr[:,j])-np.amin(nparr[:,j])
          if distance==10: 
            guessed_key[j]=np.amax(nparr[:,j])-5
            known[j]=1
      if private_key==guessed_key: 
        if i < found_min: 
            found_min=i
        if i > found_max: 
            found_max=i
        found+=i
        break
  print("found full key at iteration "+ str(found))





