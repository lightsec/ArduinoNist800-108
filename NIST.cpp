#include "NIST.h"
#include "sha256.h"
#include "sha1.h"

#if MEMORY_TEST
#include "utility/MemoryAnalyzer.h"
#endif

#if TIMING_TEST
#include "utility/TimingAnalyzer.h"
#endif

#define MIN(x, y) (((x) < (y)) ? (x) : (y))


void NIST::initialize (HMAC_type algorithm_name)
{
	hmac_algorithm = algorithm_name;
	init_prf_function();
}

/**
* Used to define PRF and PRF_init.
*/
void NIST::init_prf_function(void)
{
  switch(hmac_algorithm)
  {
    case HMAC_SHA1:
    	init_prf = &NIST::init_hmacSha1PRF;
		prf = &NIST::hmacSha1PRF;
		prfOutputSizeBit = 160;
    break;
    case HMAC_SHA256:
    	init_prf = &NIST::init_hmacSha256PRF;
		prf = &NIST::hmacSha256PRF;
		prfOutputSizeBit = 256;
    break;
    case HMAC_SHA384:
    	//not implemented
		Serial.println("Error! HMAC_SHA384 not implemented");
    break;
    case HMAC_SHA512:
    	//not implemented
    	Serial.println("Error! HMAC_SHA512 not implemented");
    break;
    default:
    	//no other algorithms available
    	Serial.println("Error! Choose an algorithm implemented");
  }
}


void NIST::init_hmacSha1PRF (uint8_t key[], int key_length)
{
  Sha1.initHmac(key, key_length);
}

uint8_t* NIST::hmacSha1PRF (uint8_t data[], int data_length)
{
	for (int y=0; y<data_length; y++) Sha1.write(data[y]);
	return (Sha1.resultHmac());
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


/**
* This funcion implements the NIST SP 800-108 specifics for KDF in Counter Mode.
* Input:
*  - keyDerivationKey: is the secret key used to derive the new key = KI
*  - outputSizeBit: is an int that represents the number of bits for the new generated key = L
*  - fixedInput: is used as fixed part of "data/message" for the hmac-shaX function.
*  - keyDerivationKey_lenght: keyDerivationKey's number bytes
*  - fixedInput_lenght: fixedInput's number bytes
* Output:
*  - derived key: is the key material generated by KDF in Counter Mode.
*/
uint8_t* NIST::KDFCounterMode(uint8_t* keyDerivationKey, int outputSizeBit, uint8_t* fixedInput, int keyDerivationKey_length, int fixedInput_length)
{

#if MEMORY_TEST
		//int fm_start = MemoryAnalyzer::freeRam_method2();
		//MemoryAnalyzer::getBinarycurrentFreeRam(1, hmac_algorithm, outputSizeBit, fm_start);
		MemoryAnalyzer::storeFreeRam(1);
#endif

#if TIMING_TEST
		//mil_start = TimingAnalyzer::getCurrentTime(); 
		//TimingAnalyzer::getBinarycurrentTime(1, hmac_algorithm, outputSizeBit, mil_start);
		TimingAnalyzer::storeTime(1);
#endif


	uint8_t ctr;
	uint8_t* KI;
	uint8_t* keyDerivated;
	uint8_t* dataInput;
	int len;
	int numCurrentElements;
	int len_bytes;
	int numCurrentElements_bytes;

	numCurrentElements = 0;
	ctr = 1;
	keyDerivated = new uint8_t[outputSizeBit/8];
	
	do{
		#if DEBUG
			Serial.print("Iteration number ");
			Serial.println(ctr);
		#endif	

		//update data using "ctr"
		dataInput = updateDataInput(ctr, fixedInput, fixedInput_length);

		//init PRF function
		(this->*init_prf)(keyDerivationKey, keyDerivationKey_length);
		
		//use the PRF to generate KI (part of keyDerivated)
		KI = (this->*prf)(dataInput, (fixedInput_length+1));

		#if DEBUG
			printBits(KI, prfOutputSizeBit);
		#endif

		//decide how many bytes (so the "length") copy for currently keyDerivated?
		if (prfOutputSizeBit >= outputSizeBit) {
			len = outputSizeBit;
		} else {
			len = MIN(prfOutputSizeBit, outputSizeBit - numCurrentElements);
		}

		//convert bits in byte
		len_bytes = len/8;
		numCurrentElements_bytes = numCurrentElements/8;

		//copy KI in part of keyDerivated
		memcpy((keyDerivated + numCurrentElements_bytes), KI, len_bytes * sizeof(uint8_t));

		//increment ctr and numCurrentElements copied in keyDerivated
		numCurrentElements = numCurrentElements + len;
		ctr++;

		//deallock space in memory
		free(dataInput);

	} while (numCurrentElements < outputSizeBit);

#if DEBUG
		printBits(keyDerivated, outputSizeBit);
#endif

#if MEMORY_TEST
		//int fm_end = MemoryAnalyzer::freeRam_method2();
		//MemoryAnalyzer::getBinarycurrentFreeRam(0, hmac_algorithm, outputSizeBit, fm_end);
		MemoryAnalyzer::storeFreeRam(0);
		MemoryAnalyzer::printBinarycurrentFreeRam(hmac_algorithm, outputSizeBit);
#endif

#if TIMING_TEST
		//long mil_end = TimingAnalyzer::getCurrentTime();
		//TimingAnalyzer::getBinarycurrentTime(0, hmac_algorithm, outputSizeBit, mil_end);
		TimingAnalyzer::storeTime(0);
		TimingAnalyzer::printBinarycurrentTime(hmac_algorithm, outputSizeBit);
#endif

	return keyDerivated;
}


/*
* Function used to shift data of 1 byte. This byte is the "ctr".
*/
uint8_t* NIST::updateDataInput (uint8_t ctr, uint8_t* fixedInput, int fixedInput_length)
{
	uint8_t* tmpFixedInput = new uint8_t[fixedInput_length + 1]; //+1 is caused from the ctr
	tmpFixedInput[0] = ctr;
	memcpy(tmpFixedInput + 1, fixedInput, fixedInput_length * sizeof(uint8_t));
	return tmpFixedInput;
}


/**
* DEBUG function to print bitsNumber.
*/
void NIST::printBits(uint8_t* hash, int bitsNumber)
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