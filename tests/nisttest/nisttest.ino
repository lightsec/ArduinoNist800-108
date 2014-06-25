#include <NIST.h>
#include "sha256.h"
#include "sha1.h"
#include <ArduinoUnit.h>


class BasicNistTest {
  protected:
    HMAC_type hmac_algorithm;
    uint8_t* keyDerivationKey;
    int outputSizeBit;
    uint8_t* fixedInput;
    int keyDerivationKey_length;
    int fixedInput_length;
    uint8_t* outputKDF;
    
    void init_keyDerivationKey(uint8_t* values, int n){
      //alloc:
      keyDerivationKey = new uint8_t[n];
      //init:
      int i;
      for(i=0; i<n; i++)
        keyDerivationKey[i] = values[i];
    }
    
    void init_fixedInput(uint8_t* values, int n){
      //alloc:
      fixedInput = new uint8_t[n];
      //init:
      int i;
      for(i=0; i<n; i++)
        fixedInput[i] = values[i];
    }
    
    void init_outputKDF(uint8_t values[], int n){
      int outputByte = n/8; 
      //alloc:
      outputKDF = new uint8_t[outputByte];  
      //init:
      int i;
      for(i=0; i<outputByte; i++)
        outputKDF[i] = values[i];
    }
   
   public:
   
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
};


/*
 * [PRF=HMAC_SHA1]
 * [CTRLOCATION=BEFORE_FIXED]
 * [RLEN=8_BITS]
 * INPUT:
 * L = 128
 * KI = 8723b723aa398f94af2b61c06cd99de01ef6497b
 * FixedInputDataByteLen = 60
 * FixedInputData = 8aece231d69ab033c9efe824c398da94777b260887c609a34c0206e4abcce0f5709356a7dbb92b8b0d387ccb4945d3b8a5490972205e72531f961b3d
 * 		Binary rep of i = 01
 * 		instring = 018aece231d69ab033c9efe824c398da94777b260887c609a34c0206e4abcce0f5709356a7dbb92b8b0d387ccb4945d3b8a5490972205e72531f961b3d
 * OUTPUT:
 * KO = 7596a2c6e19c8f5f52e1e7c6380fa5e5
 */
class NistTestOne : public TestOnce, public BasicNistTest {
  private:
    NIST nist;
    
  public:
    NistTestOne(const char *name) : TestOnce(name) 
    {    
    }
  
    void setup()
    {
        BasicNistTest::hmac_algorithm = HMAC_SHA1;
        BasicNistTest::outputSizeBit = 128;
        BasicNistTest::keyDerivationKey_length = 20;
        BasicNistTest::fixedInput_length = 60;

     uint8_t val_1[] = {
        (byte)0x87,(byte)0x23,(byte)0xb7,(byte)0x23,(byte)0xaa,(byte)0x39,(byte)0x8f,(byte)0x94,(byte)0xaf,(byte)0x2b,
	(byte)0x61,(byte)0xc0,(byte)0x6c,(byte)0xd9,(byte)0x9d,(byte)0xe0,(byte)0x1e,(byte)0xf6,(byte)0x49,(byte)0x7b
     };
     BasicNistTest::init_keyDerivationKey(val_1, 20);

     uint8_t val_2[] = {
        (byte)0x8a,(byte)0xec,(byte)0xe2,(byte)0x31,(byte)0xd6,(byte)0x9a,(byte)0xb0,(byte)0x33,(byte)0xc9,(byte)0xef,
	(byte)0xe8,(byte)0x24,(byte)0xc3,(byte)0x98,(byte)0xda,(byte)0x94,(byte)0x77,(byte)0x7b,(byte)0x26,(byte)0x08,
	(byte)0x87,(byte)0xc6,(byte)0x09,(byte)0xa3,(byte)0x4c,(byte)0x02,(byte)0x06,(byte)0xe4,(byte)0xab,(byte)0xcc,
	(byte)0xe0,(byte)0xf5,(byte)0x70,(byte)0x93,(byte)0x56,(byte)0xa7,(byte)0xdb,(byte)0xb9,(byte)0x2b,(byte)0x8b,
	(byte)0x0d,(byte)0x38,(byte)0x7c,(byte)0xcb,(byte)0x49,(byte)0x45,(byte)0xd3,(byte)0xb8,(byte)0xa5,(byte)0x49,
	(byte)0x09,(byte)0x72,(byte)0x20,(byte)0x5e,(byte)0x72,(byte)0x53,(byte)0x1f,(byte)0x96,(byte)0x1b,(byte)0x3d
      };
      BasicNistTest::init_fixedInput(val_2, 60);  
      
      uint8_t val_3[] = {
        (byte)0x75,(byte)0x96,(byte)0xa2,(byte)0xc6,(byte)0xe1,(byte)0x9c,(byte)0x8f,(byte)0x5f,(byte)0x52,(byte)0xe1,
	(byte)0xe7,(byte)0xc6,(byte)0x38,(byte)0x0f,(byte)0xa5,(byte)0xe5
      };   
      BasicNistTest::init_outputKDF(val_3, 128);
    }
    
    void once()
    {
        nist.initialize(hmac_algorithm);
        uint8_t* hashResulted = nist.KDFCounterMode(keyDerivationKey, outputSizeBit, fixedInput, keyDerivationKey_length, fixedInput_length);

        int n = outputSizeBit/8;
        int i;
        for(i=0; i<n; i++){
           assertEqual(hashResulted[i],outputKDF[i]);
        }
    } 
};



/*
 * [PRF=HMAC_SHA1]
 * [CTRLOCATION=BEFORE_FIXED]
 * [RLEN=8_BITS]
 * INPUT:
 * L = 128
 * KI = 216fe07662d332244962dd26b3dc9d4ec77783b4
 * FixedInputDataByteLen = 60
 * FixedInputData = 365047101061fd650db1c8356da8a3cc1494c0ec7f9eda7264150391ed07bcb15d86fba7399861061dd37cddbbdad38d1d4902d39ce1f0cd627965fe
 * 		Binary rep of i = 01
 * 		instring = 01365047101061fd650db1c8356da8a3cc1494c0ec7f9eda7264150391ed07bcb15d86fba7399861061dd37cddbbdad38d1d4902d39ce1f0cd627965fe
 * OUTPUT:
 * KO = 05e1a344b073117cb8743647e5320449
 */
class NistTestTwo : public TestOnce, public BasicNistTest {
  private:
    NIST nist;
    
  public:
    NistTestTwo(const char *name) : TestOnce(name) 
    {    
    }
  
    void setup()
    {
        BasicNistTest::hmac_algorithm = HMAC_SHA1;
        BasicNistTest::outputSizeBit = 128;
        BasicNistTest::keyDerivationKey_length = 20;
        BasicNistTest::fixedInput_length = 60;

     uint8_t val_1[] = {
        (byte)0x21,(byte)0x6f,(byte)0xe0,(byte)0x76,(byte)0x62,(byte)0xd3,(byte)0x32,(byte)0x24,(byte)0x49,(byte)0x62,
	(byte)0xdd,(byte)0x26,(byte)0xb3,(byte)0xdc,(byte)0x9d,(byte)0x4e,(byte)0xc7,(byte)0x77,(byte)0x83,(byte)0xb4
     };
     BasicNistTest::init_keyDerivationKey(val_1, 20);

     uint8_t val_2[] = {
        (byte)0x36,(byte)0x50,(byte)0x47,(byte)0x10,(byte)0x10,(byte)0x61,(byte)0xfd,(byte)0x65,(byte)0x0d,(byte)0xb1,
	(byte)0xc8,(byte)0x35,(byte)0x6d,(byte)0xa8,(byte)0xa3,(byte)0xcc,(byte)0x14,(byte)0x94,(byte)0xc0,(byte)0xec,
	(byte)0x7f,(byte)0x9e,(byte)0xda,(byte)0x72,(byte)0x64,(byte)0x15,(byte)0x03,(byte)0x91,(byte)0xed,(byte)0x07,
	(byte)0xbc,(byte)0xb1,(byte)0x5d,(byte)0x86,(byte)0xfb,(byte)0xa7,(byte)0x39,(byte)0x98,(byte)0x61,(byte)0x06,
	(byte)0x1d,(byte)0xd3,(byte)0x7c,(byte)0xdd,(byte)0xbb,(byte)0xda,(byte)0xd3,(byte)0x8d,(byte)0x1d,(byte)0x49,
	(byte)0x02,(byte)0xd3,(byte)0x9c,(byte)0xe1,(byte)0xf0,(byte)0xcd,(byte)0x62,(byte)0x79,(byte)0x65,(byte)0xfe
      };
      BasicNistTest::init_fixedInput(val_2, 60);  
      
      uint8_t val_3[] = {
        (byte)0x05,(byte)0xe1,(byte)0xa3,(byte)0x44,(byte)0xb0,(byte)0x73,(byte)0x11,(byte)0x7c,(byte)0xb8,(byte)0x74,
	(byte)0x36,(byte)0x47,(byte)0xe5,(byte)0x32,(byte)0x04,(byte)0x49
      };   
      BasicNistTest::init_outputKDF(val_3, 128);
    }
    
    void once()
    {
        nist.initialize(hmac_algorithm);
        uint8_t* hashResulted = nist.KDFCounterMode(keyDerivationKey, outputSizeBit, fixedInput, keyDerivationKey_length, fixedInput_length);

        int n = outputSizeBit/8;
        int i;
        for(i=0; i<n; i++){
           assertEqual(hashResulted[i],outputKDF[i]);
        }
    } 
};



/*
 * [PRF=HMAC_SHA1]
 * [CTRLOCATION=BEFORE_FIXED]
 * [RLEN=8_BITS]
 * L = 512
 * KI = eda0134ca5238efece65a5ee02bc356f4fe0d5d4
 * FixedInputDataByteLen = 60
 * FixedInputData = c8c4f85382b3e3d4acc884fdff98582d0c8c61f69d381b0c0803bef29bd4e142784522386a86ee0f864bffc5ff13eb7cb06a6e324e98eb6d561ecbb3
 * 		Binary rep of i = 01
 * 		instring = 01c8c4f85382b3e3d4acc884fdff98582d0c8c61f69d381b0c0803bef29bd4e142784522386a86ee0f864bffc5ff13eb7cb06a6e324e98eb6d561ecbb3
 * 		Binary rep of i = 02
 * 		instring = 02c8c4f85382b3e3d4acc884fdff98582d0c8c61f69d381b0c0803bef29bd4e142784522386a86ee0f864bffc5ff13eb7cb06a6e324e98eb6d561ecbb3
 * 		Binary rep of i = 03
 * 		instring = 03c8c4f85382b3e3d4acc884fdff98582d0c8c61f69d381b0c0803bef29bd4e142784522386a86ee0f864bffc5ff13eb7cb06a6e324e98eb6d561ecbb3
 * 		Binary rep of i = 04
 * 		instring = 04c8c4f85382b3e3d4acc884fdff98582d0c8c61f69d381b0c0803bef29bd4e142784522386a86ee0f864bffc5ff13eb7cb06a6e324e98eb6d561ecbb3
 * KO = 5d791c5b6a337cfb4d3b9cf73dd2afc5ff3fe1737880e54bff2f457750398b55fb4ae1c39a4c86dd72ffd453bbf4dccbeaf9a09b2e5ffe4d41f56a67898484a0
 */
class NistTestThree : public TestOnce, public BasicNistTest {
  private:
    NIST nist;
    
  public:
    NistTestThree(const char *name) : TestOnce(name) 
    {    
    }
  
    void setup()
    {
        BasicNistTest::hmac_algorithm = HMAC_SHA1;
        BasicNistTest::outputSizeBit = 512;
        BasicNistTest::keyDerivationKey_length = 20;
        BasicNistTest::fixedInput_length = 60;

     uint8_t val_1[] = {
        (byte)0xed,(byte)0xa0,(byte)0x13,(byte)0x4c,(byte)0xa5,(byte)0x23,(byte)0x8e,(byte)0xfe,(byte)0xce,(byte)0x65,
        (byte)0xa5,(byte)0xee,(byte)0x02,(byte)0xbc,(byte)0x35,(byte)0x6f,(byte)0x4f,(byte)0xe0,(byte)0xd5,(byte)0xd4
     };
     BasicNistTest::init_keyDerivationKey(val_1, 20);

     uint8_t val_2[] = {
        (byte)0xc8,(byte)0xc4,(byte)0xf8,(byte)0x53,(byte)0x82,(byte)0xb3,(byte)0xe3,(byte)0xd4,(byte)0xac,(byte)0xc8,
	(byte)0x84,(byte)0xfd,(byte)0xff,(byte)0x98,(byte)0x58,(byte)0x2d,(byte)0x0c,(byte)0x8c,(byte)0x61,(byte)0xf6,
	(byte)0x9d,(byte)0x38,(byte)0x1b,(byte)0x0c,(byte)0x08,(byte)0x03,(byte)0xbe,(byte)0xf2,(byte)0x9b,(byte)0xd4,
	(byte)0xe1,(byte)0x42,(byte)0x78,(byte)0x45,(byte)0x22,(byte)0x38,(byte)0x6a,(byte)0x86,(byte)0xee,(byte)0x0f,
	(byte)0x86,(byte)0x4b,(byte)0xff,(byte)0xc5,(byte)0xff,(byte)0x13,(byte)0xeb,(byte)0x7c,(byte)0xb0,(byte)0x6a,
	(byte)0x6e,(byte)0x32,(byte)0x4e,(byte)0x98,(byte)0xeb,(byte)0x6d,(byte)0x56,(byte)0x1e,(byte)0xcb,(byte)0xb3
      };
      BasicNistTest::init_fixedInput(val_2, 60);  
      
      uint8_t val_3[] = {
        (byte)0x5d,(byte)0x79,(byte)0x1c,(byte)0x5b,(byte)0x6a,(byte)0x33,(byte)0x7c,(byte)0xfb,(byte)0x4d,(byte)0x3b,
	(byte)0x9c,(byte)0xf7,(byte)0x3d,(byte)0xd2,(byte)0xaf,(byte)0xc5,(byte)0xff,(byte)0x3f,(byte)0xe1,(byte)0x73,
	(byte)0x78,(byte)0x80,(byte)0xe5,(byte)0x4b,(byte)0xff,(byte)0x2f,(byte)0x45,(byte)0x77,(byte)0x50,(byte)0x39,
	(byte)0x8b,(byte)0x55,(byte)0xfb,(byte)0x4a,(byte)0xe1,(byte)0xc3,(byte)0x9a,(byte)0x4c,(byte)0x86,(byte)0xdd,
	(byte)0x72,(byte)0xff,(byte)0xd4,(byte)0x53,(byte)0xbb,(byte)0xf4,(byte)0xdc,(byte)0xcb,(byte)0xea,(byte)0xf9,
	(byte)0xa0,(byte)0x9b,(byte)0x2e,(byte)0x5f,(byte)0xfe,(byte)0x4d,(byte)0x41,(byte)0xf5,(byte)0x6a,(byte)0x67,
	(byte)0x89,(byte)0x84,(byte)0x84,(byte)0xa0
      };   
      BasicNistTest::init_outputKDF(val_3, 512);
    }
    
    void once()
    {
        nist.initialize(hmac_algorithm);
        uint8_t* hashResulted = nist.KDFCounterMode(keyDerivationKey, outputSizeBit, fixedInput, keyDerivationKey_length, fixedInput_length);

        int n = outputSizeBit/8;
        int i;
        for(i=0; i<n; i++){
           assertEqual(hashResulted[i],outputKDF[i]);
        }
    } 
};


/*
 * [PRF=HMAC_SHA256]
 * [CTRLOCATION=BEFORE_FIXED]
 * [RLEN=8_BITS]
 * INPUT:
 * L = 128
 * KI = 2ce3a4a13bbf845a38999ef3c2a68385355fbbb0d6997c0bea7c3fecdc7f6745
 * FixedInputDataByteLen = 60
 * FixedInputData = 8505879d9c93d0b66a29a4d334c257a7824538ebcf151c0b55de0b757dda28fd462c17cbdd8b529f9c183b786385499ff61fa1b736fb1579cf2f8e88
 * 		Binary rep of i = 01
 * 		instring = 018505879d9c93d0b66a29a4d334c257a7824538ebcf151c0b55de0b757dda28fd462c17cbdd8b529f9c183b786385499ff61fa1b736fb1579cf2f8e88
 *	OUTPUT:
 * KO = ee9a34656d9d98384f49d35f088cd674
 */
class NistTestFour : public TestOnce, public BasicNistTest {
  private:
    NIST nist;
    
  public:
    NistTestFour(const char *name) : TestOnce(name) 
    {    
    }
  
    void setup()
    {
        BasicNistTest::hmac_algorithm = HMAC_SHA256;
        BasicNistTest::outputSizeBit = 128;
        BasicNistTest::keyDerivationKey_length = 32;
        BasicNistTest::fixedInput_length = 60;

     uint8_t val_1[] = {
        (byte)0x2c,(byte)0xe3,(byte)0xa4,(byte)0xa1,(byte)0x3b,(byte)0xbf,(byte)0x84,(byte)0x5a,(byte)0x38,(byte)0x99,
	(byte)0x9e,(byte)0xf3,(byte)0xc2,(byte)0xa6,(byte)0x83,(byte)0x85,(byte)0x35,(byte)0x5f,(byte)0xbb,(byte)0xb0,
	(byte)0xd6,(byte)0x99,(byte)0x7c,(byte)0x0b,(byte)0xea,(byte)0x7c,(byte)0x3f,(byte)0xec,(byte)0xdc,(byte)0x7f,
	(byte)0x67,(byte)0x45
     };
     BasicNistTest::init_keyDerivationKey(val_1, 32);

     uint8_t val_2[] = {
        (byte)0x85,(byte)0x05,(byte)0x87,(byte)0x9d,(byte)0x9c,(byte)0x93,(byte)0xd0,(byte)0xb6,(byte)0x6a,(byte)0x29,
	(byte)0xa4,(byte)0xd3,(byte)0x34,(byte)0xc2,(byte)0x57,(byte)0xa7,(byte)0x82,(byte)0x45,(byte)0x38,(byte)0xeb,
	(byte)0xcf,(byte)0x15,(byte)0x1c,(byte)0x0b,(byte)0x55,(byte)0xde,(byte)0x0b,(byte)0x75,(byte)0x7d,(byte)0xda,
	(byte)0x28,(byte)0xfd,(byte)0x46,(byte)0x2c,(byte)0x17,(byte)0xcb,(byte)0xdd,(byte)0x8b,(byte)0x52,(byte)0x9f,
	(byte)0x9c,(byte)0x18,(byte)0x3b,(byte)0x78,(byte)0x63,(byte)0x85,(byte)0x49,(byte)0x9f,(byte)0xf6,(byte)0x1f,
	(byte)0xa1,(byte)0xb7,(byte)0x36,(byte)0xfb,(byte)0x15,(byte)0x79,(byte)0xcf,(byte)0x2f,(byte)0x8e,(byte)0x88
      };
      BasicNistTest::init_fixedInput(val_2, 60);  
      
      uint8_t val_3[] = {
        (byte)0xee,(byte)0x9a,(byte)0x34,(byte)0x65,(byte)0x6d,(byte)0x9d,(byte)0x98,(byte)0x38,(byte)0x4f,(byte)0x49,
	(byte)0xd3,(byte)0x5f,(byte)0x08,(byte)0x8c,(byte)0xd6,(byte)0x74 
      };   
      BasicNistTest::init_outputKDF(val_3, 128);
    }
    
    void once()
    {
        nist.initialize(hmac_algorithm);
        uint8_t* hashResulted = nist.KDFCounterMode(keyDerivationKey, outputSizeBit, fixedInput, keyDerivationKey_length, fixedInput_length);

        int n = outputSizeBit/8;
        int i;
        for(i=0; i<n; i++){
           assertEqual(hashResulted[i],outputKDF[i]);
        }
    } 
};


/*
 * [PRF=HMAC_SHA256]
 * [CTRLOCATION=BEFORE_FIXED]
 * [RLEN=8_BITS]
 * INPUT:
 * L = 512
 * KI = a486b3eb053570b3b99efddcbc76685c0b53f398d581ffd8f9f372e85132d0f0
 * FixedInputDataByteLen = 60
 * FixedInputData = 3cc25799712eeb86a96f2c4abe68c4f0ba767411e8d9f9771a9e9c9085c84129ef8be7105e9542bad5798c4672a3d7cc30f35ecfcbc4b470e260e9a5
 * 		Binary rep of i = 01
 * 		instring = 013cc25799712eeb86a96f2c4abe68c4f0ba767411e8d9f9771a9e9c9085c84129ef8be7105e9542bad5798c4672a3d7cc30f35ecfcbc4b470e260e9a5
 * 		Binary rep of i = 02
 * 		instring = 023cc25799712eeb86a96f2c4abe68c4f0ba767411e8d9f9771a9e9c9085c84129ef8be7105e9542bad5798c4672a3d7cc30f35ecfcbc4b470e260e9a5
 * OUTPUT:
 * KO = 08751581291d5a4109cb10244b7a42363f0e175bce0fcd1207ec8a5ca829d80022521e8d0fa8231ce975039062e1744cc52cad7fbdc126740c905bbc0bc4a764
 */
class NistTestFive : public TestOnce, public BasicNistTest {
  private:
    NIST nist;
    
  public:
    NistTestFive(const char *name) : TestOnce(name) 
    {    
    }
  
    void setup()
    {
        BasicNistTest::hmac_algorithm = HMAC_SHA256;
        BasicNistTest::outputSizeBit = 512;
        BasicNistTest::keyDerivationKey_length = 32;
        BasicNistTest::fixedInput_length = 60;

     uint8_t val_1[] = {
        (byte)0xa4,(byte)0x86,(byte)0xb3,(byte)0xeb,(byte)0x05,(byte)0x35,(byte)0x70,(byte)0xb3,(byte)0xb9,(byte)0x9e,
	(byte)0xfd,(byte)0xdc,(byte)0xbc,(byte)0x76,(byte)0x68,(byte)0x5c,(byte)0x0b,(byte)0x53,(byte)0xf3,(byte)0x98,
	(byte)0xd5,(byte)0x81,(byte)0xff,(byte)0xd8,(byte)0xf9,(byte)0xf3,(byte)0x72,(byte)0xe8,(byte)0x51,(byte)0x32,
	(byte)0xd0,(byte)0xf0
     };
     BasicNistTest::init_keyDerivationKey(val_1, 32);

     uint8_t val_2[] = {
        (byte)0x3c,(byte)0xc2,(byte)0x57,(byte)0x99,(byte)0x71,(byte)0x2e,(byte)0xeb,(byte)0x86,(byte)0xa9,(byte)0x6f,
	(byte)0x2c,(byte)0x4a,(byte)0xbe,(byte)0x68,(byte)0xc4,(byte)0xf0,(byte)0xba,(byte)0x76,(byte)0x74,(byte)0x11,
	(byte)0xe8,(byte)0xd9,(byte)0xf9,(byte)0x77,(byte)0x1a,(byte)0x9e,(byte)0x9c,(byte)0x90,(byte)0x85,(byte)0xc8,
	(byte)0x41,(byte)0x29,(byte)0xef,(byte)0x8b,(byte)0xe7,(byte)0x10,(byte)0x5e,(byte)0x95,(byte)0x42,(byte)0xba,
	(byte)0xd5,(byte)0x79,(byte)0x8c,(byte)0x46,(byte)0x72,(byte)0xa3,(byte)0xd7,(byte)0xcc,(byte)0x30,(byte)0xf3,
	(byte)0x5e,(byte)0xcf,(byte)0xcb,(byte)0xc4,(byte)0xb4,(byte)0x70,(byte)0xe2,(byte)0x60,(byte)0xe9,(byte)0xa5
      };
      BasicNistTest::init_fixedInput(val_2, 60);  
      
      uint8_t val_3[] = {
        (byte)0x08,(byte)0x75,(byte)0x15,(byte)0x81,(byte)0x29,(byte)0x1d,(byte)0x5a,(byte)0x41,(byte)0x09,(byte)0xcb,
	(byte)0x10,(byte)0x24,(byte)0x4b,(byte)0x7a,(byte)0x42,(byte)0x36,(byte)0x3f,(byte)0x0e,(byte)0x17,(byte)0x5b,
	(byte)0xce,(byte)0x0f,(byte)0xcd,(byte)0x12,(byte)0x07,(byte)0xec,(byte)0x8a,(byte)0x5c,(byte)0xa8,(byte)0x29,
	(byte)0xd8,(byte)0x00,(byte)0x22,(byte)0x52,(byte)0x1e,(byte)0x8d,(byte)0x0f,(byte)0xa8,(byte)0x23,(byte)0x1c,
	(byte)0xe9,(byte)0x75,(byte)0x03,(byte)0x90,(byte)0x62,(byte)0xe1,(byte)0x74,(byte)0x4c,(byte)0xc5,(byte)0x2c,
	(byte)0xad,(byte)0x7f,(byte)0xbd,(byte)0xc1,(byte)0x26,(byte)0x74,(byte)0x0c,(byte)0x90,(byte)0x5b,(byte)0xbc,
	(byte)0x0b,(byte)0xc4,(byte)0xa7,(byte)0x64
      };   
      BasicNistTest::init_outputKDF(val_3, 512);
    }
    
    void once()
    {
        nist.initialize(hmac_algorithm);
        uint8_t* hashResulted = nist.KDFCounterMode(keyDerivationKey, outputSizeBit, fixedInput, keyDerivationKey_length, fixedInput_length);

        int n = outputSizeBit/8;
        int i;
        for(i=0; i<n; i++){
           assertEqual(hashResulted[i],outputKDF[i]);
        }
    } 
};


/*
 *  [PRF=HMAC_SHA256]
 * [CTRLOCATION=BEFORE_FIXED]
 * [RLEN=8_BITS]
 * INPUT:
 * L = 160
 * KI = d68684979908af0812e6b2f065b19ef6b32a148bea5cbb4ae148eb393e66102d
 * FixedInputDataByteLen = 60
 * FixedInputData = 161f7c6a503b60004cf6f0b2486975d7c8a50cbae63590fee366a1cac81f5a36a51181694b3079f03b92c534c134e89274d4a926fbdec0ca579eb43f
 * 		Binary rep of i = 01
 * 		instring = 01161f7c6a503b60004cf6f0b2486975d7c8a50cbae63590fee366a1cac81f5a36a51181694b3079f03b92c534c134e89274d4a926fbdec0ca579eb43f
 * OUTPUT:
 * KO = 9f844f2734268cc2dfddb4354db3a827748ead0f
 */
class NistTestSix : public TestOnce, public BasicNistTest {
  private:
    NIST nist;
    
  public:
    NistTestSix(const char *name) : TestOnce(name) 
    {    
    }
  
    void setup()
    {
        BasicNistTest::hmac_algorithm = HMAC_SHA256;
        BasicNistTest::outputSizeBit = 160;
        BasicNistTest::keyDerivationKey_length = 32;
        BasicNistTest::fixedInput_length = 60;

     uint8_t val_1[] = {
        (byte)0xd6,(byte)0x86,(byte)0x84,(byte)0x97,(byte)0x99,(byte)0x08,(byte)0xaf,(byte)0x08,(byte)0x12,(byte)0xe6,
	(byte)0xb2,(byte)0xf0,(byte)0x65,(byte)0xb1,(byte)0x9e,(byte)0xf6,(byte)0xb3,(byte)0x2a,(byte)0x14,(byte)0x8b,
	(byte)0xea,(byte)0x5c,(byte)0xbb,(byte)0x4a,(byte)0xe1,(byte)0x48,(byte)0xeb,(byte)0x39,(byte)0x3e,(byte)0x66,
	(byte)0x10,(byte)0x2d
     };
     BasicNistTest::init_keyDerivationKey(val_1, 32);

     uint8_t val_2[] = {
        (byte)0x16,(byte)0x1f,(byte)0x7c,(byte)0x6a,(byte)0x50,(byte)0x3b,(byte)0x60,(byte)0x00,(byte)0x4c,(byte)0xf6,
	(byte)0xf0,(byte)0xb2,(byte)0x48,(byte)0x69,(byte)0x75,(byte)0xd7,(byte)0xc8,(byte)0xa5,(byte)0x0c,(byte)0xba,
	(byte)0xe6,(byte)0x35,(byte)0x90,(byte)0xfe,(byte)0xe3,(byte)0x66,(byte)0xa1,(byte)0xca,(byte)0xc8,(byte)0x1f,
	(byte)0x5a,(byte)0x36,(byte)0xa5,(byte)0x11,(byte)0x81,(byte)0x69,(byte)0x4b,(byte)0x30,(byte)0x79,(byte)0xf0,
	(byte)0x3b,(byte)0x92,(byte)0xc5,(byte)0x34,(byte)0xc1,(byte)0x34,(byte)0xe8,(byte)0x92,(byte)0x74,(byte)0xd4,
	(byte)0xa9,(byte)0x26,(byte)0xfb,(byte)0xde,(byte)0xc0,(byte)0xca,(byte)0x57,(byte)0x9e,(byte)0xb4,(byte)0x3f
      };
      BasicNistTest::init_fixedInput(val_2, 60);  
      
      uint8_t val_3[] = {
        (byte)0x9f,(byte)0x84,(byte)0x4f,(byte)0x27,(byte)0x34,(byte)0x26,(byte)0x8c,(byte)0xc2,(byte)0xdf,(byte)0xdd,
	(byte)0xb4,(byte)0x35,(byte)0x4d,(byte)0xb3,(byte)0xa8,(byte)0x27,(byte)0x74,(byte)0x8e,(byte)0xad,(byte)0x0f
      };   
      BasicNistTest::init_outputKDF(val_3, 160);
    }
    
    void once()
    {
        nist.initialize(hmac_algorithm);
        uint8_t* hashResulted = nist.KDFCounterMode(keyDerivationKey, outputSizeBit, fixedInput, keyDerivationKey_length, fixedInput_length);

        int n = outputSizeBit/8;
        int i;
        for(i=0; i<n; i++){
           assertEqual(hashResulted[i],outputKDF[i]);
        }
    } 
};


/*
* [PRF=HMAC_SHA256]
* [CTRLOCATION=BEFORE_FIXED]
* [RLEN=8_BITS]
* INPUT:
* L = 560
* KI = d2f212cf90659f2069a43e9f7f7b102172470406658d8324b9edff6ac7a7fe52
* FixedInputDataByteLen = 60
* FixedInputData = d2d694e8f4fb4ade0e70d88222742cff975baf6622db8745fcd473793258a97e965feadd5491e4661ff18aa4f398914e9f0ffaf90738f04b158bfe9c
* 		Binary rep of i = 01
* 		instring = 01d2d694e8f4fb4ade0e70d88222742cff975baf6622db8745fcd473793258a97e965feadd5491e4661ff18aa4f398914e9f0ffaf90738f04b158bfe9c
* 		Binary rep of i = 02
* 		instring = 02d2d694e8f4fb4ade0e70d88222742cff975baf6622db8745fcd473793258a97e965feadd5491e4661ff18aa4f398914e9f0ffaf90738f04b158bfe9c
* 		Binary rep of i = 03
* 		instring = 03d2d694e8f4fb4ade0e70d88222742cff975baf6622db8745fcd473793258a97e965feadd5491e4661ff18aa4f398914e9f0ffaf90738f04b158bfe9c
* KO = 0ed1f3374d5bd9fa131af8ec168faae23c4d9e3c5e5788439ced314e8a7e46c4c5eee9ed2c7bb484bd86f99cb97906fd2efd5ffbdcaf0d8dce92f4bbd3f0fd0a79713285557d
*/
class NistTestSeven : public TestOnce, public BasicNistTest {
  private:
    NIST nist;
    
  public:
    NistTestSeven(const char *name) : TestOnce(name) 
    {
      //verbosity = TEST_VERBOSITY_ALL;      
    }
  
    void setup()
    {
        BasicNistTest::hmac_algorithm = HMAC_SHA256;
        BasicNistTest::outputSizeBit = 560;
        BasicNistTest::keyDerivationKey_length = 32;
        BasicNistTest::fixedInput_length = 60;

        //**** TODO: DELETE val_1, val_2 e val_3 ?

     uint8_t val_1[] = {
        (byte)0xd2,(byte)0xf2,(byte)0x12,(byte)0xcf,(byte)0x90,(byte)0x65,(byte)0x9f,(byte)0x20,(byte)0x69,(byte)0xa4,
	(byte)0x3e,(byte)0x9f,(byte)0x7f,(byte)0x7b,(byte)0x10,(byte)0x21,(byte)0x72,(byte)0x47,(byte)0x04,(byte)0x06,
	(byte)0x65,(byte)0x8d,(byte)0x83,(byte)0x24,(byte)0xb9,(byte)0xed,(byte)0xff,(byte)0x6a,(byte)0xc7,(byte)0xa7,
	(byte)0xfe,(byte)0x52
     };
     BasicNistTest::init_keyDerivationKey(val_1, 32);

     uint8_t val_2[] = {
        (byte)0xd2,(byte)0xd6,(byte)0x94,(byte)0xe8,(byte)0xf4,(byte)0xfb,(byte)0x4a,(byte)0xde,(byte)0x0e,(byte)0x70,
	(byte)0xd8,(byte)0x82,(byte)0x22,(byte)0x74,(byte)0x2c,(byte)0xff,(byte)0x97,(byte)0x5b,(byte)0xaf,(byte)0x66,
	(byte)0x22,(byte)0xdb,(byte)0x87,(byte)0x45,(byte)0xfc,(byte)0xd4,(byte)0x73,(byte)0x79,(byte)0x32,(byte)0x58,
	(byte)0xa9,(byte)0x7e,(byte)0x96,(byte)0x5f,(byte)0xea,(byte)0xdd,(byte)0x54,(byte)0x91,(byte)0xe4,(byte)0x66,
	(byte)0x1f,(byte)0xf1,(byte)0x8a,(byte)0xa4,(byte)0xf3,(byte)0x98,(byte)0x91,(byte)0x4e,(byte)0x9f,(byte)0x0f,
	(byte)0xfa,(byte)0xf9,(byte)0x07,(byte)0x38,(byte)0xf0,(byte)0x4b,(byte)0x15,(byte)0x8b,(byte)0xfe,(byte)0x9c
      };
      BasicNistTest::init_fixedInput(val_2, 60);  
      
      uint8_t val_3[] = {
        (byte)0x0e,(byte)0xd1,(byte)0xf3,(byte)0x37,(byte)0x4d,(byte)0x5b,(byte)0xd9,(byte)0xfa,(byte)0x13,(byte)0x1a,
	(byte)0xf8,(byte)0xec,(byte)0x16,(byte)0x8f,(byte)0xaa,(byte)0xe2,(byte)0x3c,(byte)0x4d,(byte)0x9e,(byte)0x3c,
	(byte)0x5e,(byte)0x57,(byte)0x88,(byte)0x43,(byte)0x9c,(byte)0xed,(byte)0x31,(byte)0x4e,(byte)0x8a,(byte)0x7e,
	(byte)0x46,(byte)0xc4,(byte)0xc5,(byte)0xee,(byte)0xe9,(byte)0xed,(byte)0x2c,(byte)0x7b,(byte)0xb4,(byte)0x84,
	(byte)0xbd,(byte)0x86,(byte)0xf9,(byte)0x9c,(byte)0xb9,(byte)0x79,(byte)0x06,(byte)0xfd,(byte)0x2e,(byte)0xfd,
	(byte)0x5f,(byte)0xfb,(byte)0xdc,(byte)0xaf,(byte)0x0d,(byte)0x8d,(byte)0xce,(byte)0x92,(byte)0xf4,(byte)0xbb,
	(byte)0xd3,(byte)0xf0,(byte)0xfd,(byte)0x0a,(byte)0x79,(byte)0x71,(byte)0x32,(byte)0x85,(byte)0x55,(byte)0x7d
      };   
      BasicNistTest::init_outputKDF(val_3, 560);
    }
    
    void once()
    {
        nist.initialize(hmac_algorithm);
        uint8_t* hashResulted = nist.KDFCounterMode(keyDerivationKey, outputSizeBit, fixedInput, keyDerivationKey_length, fixedInput_length);

        //TODO - to improve the asser, it could be usefull convert in to STRING?????
        int n = outputSizeBit/8;
        int i;
        for(i=0; i<n; i++){
           assertEqual(hashResulted[i],outputKDF[i]);
        }
    } 
};

NistTestOne myTest1("> Test 1 (HMAC_SHA1) <");
NistTestTwo myTest2("> Test 2 (HMAC_SHA1) <");
NistTestThree myTest3("> Test 3 (HMAC_SHA1) <");
NistTestFour myTest4("> Test 4 (HMAC_SHA256) <");
NistTestFive myTest5("> Test 5 (HMAC_SHA256) <");
NistTestSix myTest6("> Test 6 (HMAC_SHA256) <");
NistTestSeven myTest7("> Test 7 (HMAC_SHA256) <");

void setup()
{
  Serial.begin(9600);
}

void loop()
{
  Test::run();
}
