#ifndef TIMINGANALYZER_H
#define TIMINGANALYZER_H

#include "Arduino.h"
#include "../HMAC_type.h"

class TimingAnalyzer
{
	public:
		static String getSTRcurrentTime(String when, HMAC_type algorithm, size_t numBitOutputKDF, long mil);
		static String getJSONcurrentTime(String when, HMAC_type algorithm, size_t numBitOutputKDF, long mil);
		static String getBinarycurrentTime(bool when, HMAC_type algorithm, size_t numBitOutputKDF, long mil);
		static long getCurrentTime();
};

#endif