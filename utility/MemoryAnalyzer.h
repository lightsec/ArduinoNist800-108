#ifndef MEMORYANALYZER_H
#define MEMORYANALYZER_H

#include "Arduino.h"
#include "../HMAC_type.h"

class MemoryAnalyzer
{
	private:
		static int freeRam();
		static int freeRam_method2();

	public:
		static String getCurrentFreeRam (String when, HMAC_type algorithm, size_t numBitOutputKDF);
};

#endif