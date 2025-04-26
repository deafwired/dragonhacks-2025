#include <Arduino.h>
#include <LiquidCrystal_I2C.h>

// put function declarations here:
int myFunction(int, int);

void setup() {
  Serial.begin(9600);
}

void loop() {
  Serial.println("Looping...");
}

// put function definitions here:
int myFunction(int x, int y) {
  return x + y;
}