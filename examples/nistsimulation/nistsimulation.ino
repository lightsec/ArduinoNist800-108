#include <NIST.h>
#include "sha256.h"
#include "sha1.h"
#include <Time.h>


//used to convert long in uint8_t*
union longBytes {
    long value; //arduino long = 4 bytes
    uint8_t split[4];
};

//struct to contain secret keys
struct MS {
  uint8_t* MSencr;
  uint8_t* MSauth;
  size_t MSencrBits;
  size_t MSauthBits;
} secretKeys;


NIST nist;


/**
* In each simulation, new random MS keys (MSauth and MSencr) are generated.
* This file is compose by 3 simulations:
* - HMAC_SHA1 and MSauth and MSencr long 128 bits
* - HMAC_SHA256 and MSauth and MSencr long 256 bits
* - HMAC_SHA256 and MSauth and MSencr long 512 bits
* All fixed data are generated using random functions.
* At the end of each simulation, the memory is cleaned. 
* In this way, each simulation start in the same memory condition.
*/
void setup()
{
  Serial.begin(9600);

  simulateKDF(128, HMAC_SHA1);
  simulateKDF(256, HMAC_SHA256);
  simulateKDF(512, HMAC_SHA256);
}

void simulateKDF(size_t numBitsOutputKey, HMAC_type algorithmType)
{
  // if analog input pin 0 is unconnected, random analog
  // noise will cause the call to randomSeed() to generate
  // different seed numbers each time the sketch runs.
  // randomSeed() will then shuffle the random function.
  randomSeed(analogRead(0));
  //set nist PRF
  nist.initialize(algorithmType);
  //generate random secrets keys
  generateMSkeys(numBitsOutputKey);
  //execute simulation
  executeSimulation(numBitsOutputKey);
}


void generateMSkeys(size_t numBitsLength)
{
  secretKeys.MSencrBits = numBitsLength;
  secretKeys.MSauthBits = numBitsLength;
  secretKeys.MSencr = generateRandomBytes(numBitsLength/8);
  secretKeys.MSauth = generateRandomBytes(numBitsLength/8);
  //printBits(secretKeys.MSencr, secretKeys.MSencrBits);
  //printBits(secretKeys.MSauth, secretKeys.MSauthBits);
}

void executeSimulation(size_t numBitsOutputKey)
{
  time_t init_time = now();
  time_t exp_time = (second(init_time) + 3600000);

  uint8_t* Kencr = generateKDFkey(secretKeys.MSencr, secretKeys.MSencrBits, random(), random(), init_time, exp_time, numBitsOutputKey);
  uint8_t* Kauth = generateKDFkey(secretKeys.MSauth, secretKeys.MSauthBits, random(), random(), init_time, exp_time, numBitsOutputKey);

  printBits(Kencr, numBitsOutputKey);
  printBits(Kauth, numBitsOutputKey);

  //free memory used for simulation (necessary to clean memory for next simulations)
  freeMemory(Kencr, Kauth);
}


uint8_t* generateKDFkey(uint8_t* key, size_t keyLength, int a, int userID, time_t init_time, time_t exp_time, size_t outputSizeBit)
{
  uint8_t* resultKDF;
  int fixedInputLength = (sizeof(a) + 1 + sizeof(userID) + sizeof(init_time) + sizeof(exp_time) + 4);
  //build the info array: a || 0x00 || userID || init_time || exp_time || [outputSizeBits]2
  uint8_t* fixedInput = new uint8_t[fixedInputLength];
  
  fixedInput[0] = a;
  fixedInput[sizeof(a)] = (uint8_t)0x00;
  fixedInput[sizeof(a)+1] = userID;
  fixedInput[sizeof(userID)] = init_time;
  fixedInput[sizeof(init_time)] = exp_time;
  fixedInput[sizeof(exp_time)] = outputSizeBit;
  
  resultKDF = nist.KDFCounterMode(key, outputSizeBit, fixedInput, keyLength, fixedInputLength);

  //dealloc fixedInput to clean the memory
  free(fixedInput);
  
  return resultKDF;
}


void freeMemory(uint8_t* Kencr, uint8_t* Kauth)
{
  //dealloc all data for the next simulation
  free(Kencr);
  free(Kauth);
  free(secretKeys.MSencr);
  free(secretKeys.MSauth);
}


void loop()
{
}


//UTILITY FUNCTION:
void printBits(uint8_t* hash, int bitsNumber)
{
  int i;
  int limit = bitsNumber/8;

  for (i=0; i<limit; i++)
  {
    Serial.print("0123456789abcdef"[hash[i]>>4]);
    Serial.print("0123456789abcdef"[hash[i]&0xf]);
  }
  Serial.println();
}


//UTILITY FUNCTION:
uint8_t* generateRandomBytes(int keySize)
{
  uint8_t* key = new uint8_t[keySize];
  union longBytes tmp;
  int i;
  for(i=0; i < keySize; i=i+4){
    tmp.value = random();
    memcpy((key + i), tmp.split, 4 * sizeof(uint8_t));
  }
  return key;
}