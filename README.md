ArduinoNist800-108
====

This project contains an Arduino Library that implements Nist SP 800-108 KDF in Counter Mode.

## Installation

Follow these steps to install this library:

1. Download this repository in your [Arduino Libraries Directory](http://arduino.cc/en/Guide/Libraries) e.g. `<arduino installation directory>\libraries`.
1. Download the [Cryptosuite Library](https://github.com/dventura3/Cryptosuite) in the Arduino Library Directory. Note that some changes have been introduced in the original Cryptosuite Library.

Inside the file Nist.h there are 3 constants:

* #define DEBUG 0 => to print in the serial monitor verbose information;
* #define MEMORY_TEST 0 => to know how much free memory is available at starting and ending execution of NIST-KDF function;
* #define TIMING_TEST 0 => to know how much time was spent to execute NIST-KDF function.

To enable this information, it's necessary to set to "1" the value of one o more of these constants.

## Testing

For the unit test, this project uses the [ArduinoUnit Library](https://github.com/mmurdoch/arduinounit).
So, first of all, it is necessary to download the library inside Arduino Library Directory.
After that, it is possible to execute the test branch contained inside `<arduino installation directory>\libraries\nist\tests` directory.

## Examples

The ''examples'' directory contains three examples: ''nistexample'', ''nistsimulation'' or ''nistchaching''.

To execute any of them is necessary to download the [Arduino Time Library](http://playground.arduino.cc/Code/Time).
