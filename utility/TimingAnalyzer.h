#ifndef TIMINGANALYZER_H
#define TIMINGANALYZER_H

#include "Arduino.h"
#include "../HMAC_type.h"

class TimingAnalyzer
{
	public:
		static String getSTRCurrentTime(String when, HMAC_type algorithm, size_t numBitOutputKDF, long mil);
		static String getJSONcurrentTime(String when, HMAC_type algorithm, size_t numBitOutputKDF, long mil);
		static long getCurrentTime();
};

#endif