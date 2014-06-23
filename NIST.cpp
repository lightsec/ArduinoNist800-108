#include "NIST.h"

void NIST::initialize (HMAC_type algorithm_name)
{
	hmac_algorithm = algorithm_name;
  	Serial.println("Hello World From Nist Library");
}