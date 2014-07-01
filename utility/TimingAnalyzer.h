#ifndef TIMINGANALYZER_H
#define TIMINGANALYZER_H

#include "Arduino.h"
#include "../HMAC_type.h"

class TimingAnalyzer
{
	public:
		static String getCurrentTime (String when, HMAC_type algorithm, size_t numBitOutputKDF);
};

#endif