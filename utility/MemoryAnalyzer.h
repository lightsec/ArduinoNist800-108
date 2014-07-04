#ifndef MEMORYANALYZER_H
#define MEMORYANALYZER_H

#include "Arduino.h"
#include "../HMAC_type.h"

class MemoryAnalyzer
{
	private:
		static int freeRam();

	public:
		static String getSTRCurrentFreeRam (String when, HMAC_type algorithm, size_t numBitOutputKDF, int freeRam);
		static String getJSONcurrentFreeRam(String when, HMAC_type algorithm, size_t numBitOutputKDF, int freeRam);
		static int freeRam_method2();
};

#endif