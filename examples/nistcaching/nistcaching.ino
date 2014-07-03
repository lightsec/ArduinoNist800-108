#include <NIST.h>
#include "sha256.h"
#include "sha1.h"
#include <Time.h>
#include "LinkedList.h"


//used to convert long in uint8_t*
union longBytes {
    long value; //arduino long = 4 bytes
    uint8_t split[4];
};

//struct to contain secret keys
struct MS {
  uint8_t* MSencr;
  uint8_t* MSauth;
  size_t MSencrBits;
  size_t MSauthBits;
} secretKeys;

//struct used to store users data
struct userData {
  uint8_t* Kencr_sa;
  uint8_t* Kauth_sa;
  time_t exp_time;
  int ctr;
  int ID_A; //user id
};


NIST nist;

size_t numBitsOutputKey = 512;
HMAC_type algorithmType = HMAC_SHA256;

int currentActiveUsers = 0;
Node<struct userData>* root = NULL;


void setup()
{
  Serial.begin(9600);

  initParameters(numBitsOutputKey, algorithmType);
}

void initParameters(size_t numBitsOutputKey, HMAC_type algorithmType)
{
  //set seed for random function
  randomSeed(analogRead(0));
  //set nist PRF
  nist.initialize(algorithmType);
  //generate random secrets keys
  generateMSkeys(numBitsOutputKey);
}


void generateMSkeys(size_t numBitsLength)
{
  secretKeys.MSencrBits = numBitsLength;
  secretKeys.MSauthBits = numBitsLength;
  secretKeys.MSencr = generateRandomBytes(numBitsLength/8);
  secretKeys.MSauth = generateRandomBytes(numBitsLength/8);
}

void executeSimulation(size_t numBitsOutputKey)
{
  time_t init_time = now();
  time_t exp_time = (second(init_time) + 3600000);

  uint8_t* Kencr = generateKDFkey(secretKeys.MSencr, secretKeys.MSencrBits, random(), random(), init_time, exp_time, numBitsOutputKey);
  uint8_t* Kauth = generateKDFkey(secretKeys.MSauth, secretKeys.MSauthBits, random(), random(), init_time, exp_time, numBitsOutputKey);
  
  //create the struct to store user data
  struct userData ud;
  ud.Kencr_sa = Kencr;
  ud.Kauth_sa = Kauth;
  ud.exp_time = exp_time;
  ud.ctr = random();
  ud.ID_A = random();
  //add the new node-user in the linked list of all active users
  if(currentActiveUsers==0){
     root = create_node(ud);
  }else{
    Node<struct userData>* newNode = create_node(ud);
    insert_node_first(root, newNode);
  }
  currentActiveUsers++;
  Serial.println(currentActiveUsers);
}


uint8_t* generateKDFkey(uint8_t* key, size_t keyLength, int a, int userID, time_t init_time, time_t exp_time, size_t outputSizeBit)
{
  uint8_t* resultKDF;
  int fixedInputLength = (sizeof(a) + 1 + sizeof(userID) + sizeof(init_time) + sizeof(exp_time) + 4);
  //build the info array: a || 0x00 || userID || init_time || exp_time || [outputSizeBits]2
  uint8_t* fixedInput = new uint8_t[fixedInputLength];
  
  fixedInput[0] = a;
  fixedInput[sizeof(a)] = (uint8_t)0x00;
  fixedInput[sizeof(a)+1] = userID;
  fixedInput[sizeof(userID)] = init_time;
  fixedInput[sizeof(init_time)] = exp_time;
  fixedInput[sizeof(exp_time)] = outputSizeBit;
  
  resultKDF = nist.KDFCounterMode(key, outputSizeBit, fixedInput, keyLength, fixedInputLength);

  //dealloc fixedInput to clean the memory
  free(fixedInput);
  
  return resultKDF;
}


void loop()
{
  //execute simulation
  executeSimulation(numBitsOutputKey);
}


//UTILITY FUNCTION:
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


//UTILITY FUNCTION:
uint8_t* generateRandomBytes(int keySize)
{
  uint8_t* key = new uint8_t[keySize];
  union longBytes tmp;
  int i;
  for(i=0; i < keySize; i=i+4){
    tmp.value = random();
    memcpy((key + i), tmp.split, 4 * sizeof(uint8_t));
  }
  return key;
}
