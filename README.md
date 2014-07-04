Nist
====

Arduino Library that implements Nist SP 800-108 KDF in Counter Mode

##How Installing The Library?

To use this libray, two operations have to be done:
* Download this repository in your [Arduino Libraries Directory](http://arduino.cc/en/Guide/Libraries) e.g. `<arduino installation directory>\libraries`.
* Download the [Cryptosuite Library](https://github.com/dventura3/Cryptosuite) in the Arduino Library Directory. (NB: The Cryptosuite Library was modified respect to the original version).

Inside the file Nist.h there are 3 constants:
* #define DEBUG 0 => to print in the serial monitor verbose information;
* #define MEMORY_TEST 0 => to know how much free memory is available at starting and ending execution of NIST-KDF function;
* #define TIMING_TEST 0 => to know how much time was spent to execute NIST-KDF function.

For enabling this information, it's necessary to set to "1" the value of one o more of these constants.

##How Testing The Library?

To test the libray, it was used [ArduinoUnit Library](https://github.com/mmurdoch/arduinounit).
So, first of all, it is necessary to download the library inside Arduino Library Directory.
After that, it is possible to execute the test branch contained inside `<arduino installation directory>\libraries\nist\tests` directory.

##Examples

In the directory ''examples'' of this repository, there are two examples.

To execute the ''nistsimulation'' or ''nistchaching'' is necessary to download the [Arduino Time Library](http://playground.arduino.cc/Code/Time).
