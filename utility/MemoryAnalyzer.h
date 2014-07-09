#ifndef MEMORYANALYZER_H
#define MEMORYANALYZER_H

#include "Arduino.h"
#include "../HMAC_type.h"

#define MEM_BUF_SIZE 2

class MemoryAnalyzer
{
	private:
		static int freeRam();

	protected:
		static int* bufMemory;

	public:
		static String getSTRcurrentFreeRam (String when, HMAC_type algorithm, size_t numBitOutputKDF, int freeRam);
		static String getJSONcurrentFreeRam(String when, HMAC_type algorithm, size_t numBitOutputKDF, int freeRam);
		static String getBinarycurrentFreeRam(bool when, HMAC_type algorithm, size_t numBitOutputKDF, int freeRam);
		static int freeRam_method2();
		static void storeFreeRam(int position);
		static void printBinarycurrentFreeRam(HMAC_type algorithm, size_t numBitOutputKDF);
};

#endif