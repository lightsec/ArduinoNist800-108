#ifndef TIMINGANALYZER_H
#define TIMINGANALYZER_H

#include "Arduino.h"
#include "../HMAC_type.h"

#define TIME_BUF_SIZE 2

class TimingAnalyzer
{
	protected:
		static long* bufTime;

	public:
		static String getSTRcurrentTime(String when, HMAC_type algorithm, size_t numBitOutputKDF, long mil);
		static String getJSONcurrentTime(String when, HMAC_type algorithm, size_t numBitOutputKDF, long mil);
		static String getBinarycurrentTime(bool when, HMAC_type algorithm, size_t numBitOutputKDF, long mil);
		static long getCurrentTime();
		static void storeTime(int position);
		static void printBinarycurrentTime(HMAC_type algorithm, size_t numBitOutputKDF);
};

#endif