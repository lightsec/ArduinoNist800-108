#include "NIST.h"
#include "sha256.h"
#include "sha1.h"

void NIST::initialize (HMAC_type algorithm_name)
{
	hmac_algorithm = algorithm_name;

	//TODO - DYNAMIC
	init_prf = &NIST::init_hmacSha256PRF;
	prf = &NIST::hmacSha256PRF;
}


void NIST::init_hmacSha1PRF (uint8_t key[], int key_length)
{
  Sha1.initHmac(key, key_length);
}

uint8_t* NIST::hmacSha1PRF (uint8_t data[], int data_length)
{
	for (int y=0; y<data_length; y++) Sha1.write(data[y]);
	return Sha1.resultHmac();
}

void NIST::init_hmacSha256PRF (uint8_t key[], int key_length)
{
  Sha256.initHmac(key, key_length);
}

uint8_t* NIST::hmacSha256PRF(uint8_t data[], int data_length)
{
	for (int y=0; y<data_length; y++) Sha256.write(data[y]);
	return Sha256.resultHmac();
}

/*
* TODO
*/
uint8_t* NIST::KDFCounterMode(uint8_t* keyDerivationKey, int outputSizeBit, uint8_t* fixedInput, int keyDerivationKey_lenght, int fixedInput_lenght)
{
	uint8_t* hash;
	(this->*init_prf)(keyDerivationKey, keyDerivationKey_lenght);
	hash = (this->*prf)(fixedInput, fixedInput_lenght);
	return hash;
}


/**
* Utility Function: Print the Result of HMAC-SHA1 algorithm
*/
void NIST::printSha1(uint8_t* hash)
{
  int i;
  for (i=0; i<20; i++)
  {
    Serial.print("0123456789abcdef"[hash[i]>>4]);
    Serial.print("0123456789abcdef"[hash[i]&0xf]);
  }
  Serial.println();
}

/**
* Utility Function: Print the Result of HMAC-SHA256 algorithm
*/
void NIST::printSha256(uint8_t* hash)
{
  int i;
  for (i=0; i<32; i++)
  {
    Serial.print("0123456789abcdef"[hash[i]>>4]);
    Serial.print("0123456789abcdef"[hash[i]&0xf]);
  }
  Serial.println();
}