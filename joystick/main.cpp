#include <Arduino.h>

// Pin setup
const int xPin = A0; // Joystick X-axis
const int yPin = A1; // Joystick Y-axis
const int buttonPin = 2; // Joystick button (digital)

// Thresholds
const int threshold = 200; // Sensitivity adjustment
const unsigned long debounceDelay = 200; // Debounce time in milliseconds

// Last movement tracking
String lastMove = "";
unsigned long lastDebounceTime = 0;

// Button debouncing
bool lastButtonState = HIGH;
unsigned long lastButtonDebounceTime = 0;
bool buttonClicked = false;

void setup() {
  Serial.begin(9600); // Start serial communication
  pinMode(xPin, INPUT);
  pinMode(yPin, INPUT);
  pinMode(buttonPin, INPUT_PULLUP); // Button uses internal pull-up resistor
  Serial.println("Joystick Initialized");
}

void loop() {
  int xVal = analogRead(xPin);
  int yVal = analogRead(yPin);
  int buttonState = digitalRead(buttonPin); // Read the digital button state

  // Joystick movement tracking
  String currentMove = "";

  if (xVal < (512 - threshold)) {
    currentMove = "Left";
  }
  else if (xVal > (512 + threshold)) {
    currentMove = "Right";
  }
  else if (yVal < (512 - threshold)) {
    currentMove = "Down";
  }
  else if (yVal > (512 + threshold)) {
    currentMove = "Up";
  } else if (buttonState == 0) {
    currentMove = "Click";
  }

  // Movement debounce
  if (currentMove != lastMove && (millis() - lastDebounceTime) > debounceDelay) {
    if (currentMove != "") {
      Serial.println(currentMove); // Print only when movement is detected
    }
    lastMove = currentMove;
    lastDebounceTime = millis();
  }

  // Button debounce logic
  if (buttonState != lastButtonState) {
    lastButtonDebounceTime = millis(); // Update debounce time
  }

  // Print "Click!" only when the button is pressed and released
  if ((millis() - lastButtonDebounceTime) > debounceDelay) {
    if (buttonState == LOW && lastButtonState == HIGH) { 
      Serial.println("Click!"); // Print "Click!" when button is pressed
    }
  }

  lastButtonState = buttonState;

  delay(10); // Small delay to reduce CPU usage
}