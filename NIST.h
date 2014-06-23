#ifndef NIST_H
#define NIST_H

#include "Arduino.h"
#include "inttypes.h"
#include "HMAC_type.h"

class NIST
{

	private:
		HMAC_type hmac_algorithm;

	public:
		void initialize (HMAC_type algorithm_name);
};

#endif