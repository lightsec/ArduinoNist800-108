#include <NIST.h>
#include "sha256.h"
#include "sha1.h"
#include <MemoryFree.h>

//used to count how many elements there are inside an array
#define SIZE(x)  (sizeof(x) / sizeof(x[0]))


NIST nist;

//TEST 1 - HMAC_SHA1

uint8_t keyTest1[] = {
  (byte)0x87,(byte)0x23,(byte)0xb7,(byte)0x23,(byte)0xaa,(byte)0x39,(byte)0x8f,(byte)0x94,(byte)0xaf,(byte)0x2b,
  (byte)0x61,(byte)0xc0,(byte)0x6c,(byte)0xd9,(byte)0x9d,(byte)0xe0,(byte)0x1e,(byte)0xf6,(byte)0x49,(byte)0x7b
};

uint8_t fixedInput1[] = {
  (byte)0x8a,(byte)0xec,(byte)0xe2,(byte)0x31,(byte)0xd6,(byte)0x9a,(byte)0xb0,(byte)0x33,(byte)0xc9,(byte)0xef,
  (byte)0xe8,(byte)0x24,(byte)0xc3,(byte)0x98,(byte)0xda,(byte)0x94,(byte)0x77,(byte)0x7b,(byte)0x26,(byte)0x08,
  (byte)0x87,(byte)0xc6,(byte)0x09,(byte)0xa3,(byte)0x4c,(byte)0x02,(byte)0x06,(byte)0xe4,(byte)0xab,(byte)0xcc,
  (byte)0xe0,(byte)0xf5,(byte)0x70,(byte)0x93,(byte)0x56,(byte)0xa7,(byte)0xdb,(byte)0xb9,(byte)0x2b,(byte)0x8b,
  (byte)0x0d,(byte)0x38,(byte)0x7c,(byte)0xcb,(byte)0x49,(byte)0x45,(byte)0xd3,(byte)0xb8,(byte)0xa5,(byte)0x49,
  (byte)0x09,(byte)0x72,(byte)0x20,(byte)0x5e,(byte)0x72,(byte)0x53,(byte)0x1f,(byte)0x96,(byte)0x1b,(byte)0x3d
};


//TEST 2 - HMAC_SHA256

uint8_t keyTest2[] =  {
  (byte)0xa4,(byte)0x86,(byte)0xb3,(byte)0xeb,(byte)0x05,(byte)0x35,(byte)0x70,(byte)0xb3,(byte)0xb9,(byte)0x9e,
  (byte)0xfd,(byte)0xdc,(byte)0xbc,(byte)0x76,(byte)0x68,(byte)0x5c,(byte)0x0b,(byte)0x53,(byte)0xf3,(byte)0x98,
  (byte)0xd5,(byte)0x81,(byte)0xff,(byte)0xd8,(byte)0xf9,(byte)0xf3,(byte)0x72,(byte)0xe8,(byte)0x51,(byte)0x32,
  (byte)0xd0,(byte)0xf0
};

uint8_t fixedInput2[] =  {
  (byte)0x3c,(byte)0xc2,(byte)0x57,(byte)0x99,(byte)0x71,(byte)0x2e,(byte)0xeb,(byte)0x86,(byte)0xa9,(byte)0x6f,
  (byte)0x2c,(byte)0x4a,(byte)0xbe,(byte)0x68,(byte)0xc4,(byte)0xf0,(byte)0xba,(byte)0x76,(byte)0x74,(byte)0x11,
  (byte)0xe8,(byte)0xd9,(byte)0xf9,(byte)0x77,(byte)0x1a,(byte)0x9e,(byte)0x9c,(byte)0x90,(byte)0x85,(byte)0xc8,
  (byte)0x41,(byte)0x29,(byte)0xef,(byte)0x8b,(byte)0xe7,(byte)0x10,(byte)0x5e,(byte)0x95,(byte)0x42,(byte)0xba,
  (byte)0xd5,(byte)0x79,(byte)0x8c,(byte)0x46,(byte)0x72,(byte)0xa3,(byte)0xd7,(byte)0xcc,(byte)0x30,(byte)0xf3,
  (byte)0x5e,(byte)0xcf,(byte)0xcb,(byte)0xc4,(byte)0xb4,(byte)0x70,(byte)0xe2,(byte)0x60,(byte)0xe9,(byte)0xa5
};


void setup()
{
  
  Serial.begin(9600);

  //initialization for hmac-sha1
  nist.initialize(HMAC_SHA1);
  
  //TEST 1 - HMAC_SHA1
  uint8_t* hash1 = nist.KDFCounterMode(keyTest1, 128, fixedInput1, SIZE(keyTest1), SIZE(fixedInput1));
  Serial.print("[HMAC-SHA1] [RESULTED] ");
  printBits(hash1, 128);
  Serial.print("[HMAC-SHA1] [EXPECTED] ");
  Serial.println("7596a2c6e19c8f5f52e1e7c6380fa5e5");
  free(hash1);
  
  //new initialization for hmac-sha256
  nist.initialize(HMAC_SHA256);
  
  //TEST 2 - HMAC_SHA256
  uint8_t* hash2 = nist.KDFCounterMode(keyTest2, 512, fixedInput2, SIZE(keyTest2), SIZE(fixedInput2));
  Serial.print("[HMAC-SHA256] [RESULTED] ");
  printBits(hash2, 512);
  Serial.print("[HMAC-SHA256] [EXPECTED] ");
  Serial.println("08751581291d5a4109cb10244b7a42363f0e175bce0fcd1207ec8a5ca829d80022521e8d0fa8231ce975039062e1744cc52cad7fbdc126740c905bbc0bc4a764");
  free(hash2);
  
}

void loop()
{
}

//UTILITY FUNCTION
void printBits(uint8_t* hash, int bitsNumber)
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