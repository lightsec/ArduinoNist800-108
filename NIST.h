#ifndef NIST_H
#define NIST_H

#include "Arduino.h"
#include "inttypes.h"
#include "HMAC_type.h"

#define DEBUG 1

class NIST
{

	private:
		HMAC_type hmac_algorithm;
		void (NIST::*init_prf) (uint8_t key[], int key_length);
    	uint8_t* (NIST::*prf) (uint8_t data[], int data_length);
    	void (NIST::*print_prf_result) (uint8_t* hash);

    	//init hmac-shaX function
    	void init_prf_function(void);

    	//sha-1 functions
    	void init_hmacSha1PRF (uint8_t key[], int key_length);
    	uint8_t* hmacSha1PRF (uint8_t data[], int data_length);
    	void printSha1(uint8_t* hash);

    	//sha-256 functions
   		void init_hmacSha256PRF (uint8_t key[], int key_length);
    	uint8_t* hmacSha256PRF(uint8_t data[], int data_length);
		void printSha256(uint8_t* hash);

	public:
		void initialize (HMAC_type algorithm_name);
		uint8_t* KDFCounterMode(uint8_t* keyDerivationKey, int outputSizeBit, uint8_t* fixedInput, int keyDerivationKey_lenght, int fixedInput_lenght);
    	
};

#endif