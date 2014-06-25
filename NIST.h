#ifndef NIST_H
#define NIST_H

#include "Arduino.h"
#include "inttypes.h"
#include "HMAC_type.h"

#define DEBUG 0

class NIST
{

	private:
		HMAC_type hmac_algorithm;
		int prfOutputSizeBit; // = h for NIST specifics
		void (NIST::*init_prf) (uint8_t key[], int key_length);
    	uint8_t* (NIST::*prf) (uint8_t data[], int data_length);

    	//init PRF function
    	void init_prf_function(void);

    	//sha-1 functions
    	void init_hmacSha1PRF (uint8_t key[], int key_length);
    	uint8_t* hmacSha1PRF (uint8_t data[], int data_length);

    	//sha-256 functions
   		void init_hmacSha256PRF (uint8_t key[], int key_length);
    	uint8_t* hmacSha256PRF(uint8_t data[], int data_length);

		//utilities
		uint8_t* updateDataInput (uint8_t ctr, uint8_t* fixedInput, int fixedInput_length);
		void printBits(uint8_t* hash, int bitsNumber);

	public:
		void initialize (HMAC_type algorithm_name);
		uint8_t* KDFCounterMode(uint8_t* keyDerivationKey, int outputSizeBit, uint8_t* fixedInput, int keyDerivationKey_length, int fixedInput_length);
};

#endif