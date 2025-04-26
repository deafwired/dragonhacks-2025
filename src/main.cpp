#include <Arduino.h>
#include <LiquidCrystal_I2C.h>
#include <SPI.h>
#include <MFRC522.h>
#include <uECC.h>
// #include <String.h>

#define RST_PIN 5 // Configurable, see typical pin layout above
#define SS_PIN 53 // Configurable, see typical pin layout above

MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance

// Define the structure to hold the key pair
struct EccKeyPair {
    uint8_t publicKey[64];
    uint8_t privateKey[32];
    bool success; // Flag to indicate if generation succeeded
  };

const int lcdColumns = 16;
const int lcdRows = 2;
LiquidCrystal_I2C lcd(0x27, lcdColumns, lcdRows);

// Function Prototypes
void setLCDMessageCentered(String message, int row);
EccKeyPair generateKeys();
int customRNG(uint8_t *dest, unsigned size); // Added prototype for customRNG

// RNG Function Implementation
int customRNG(uint8_t *dest, unsigned size) {
    // Use Arduino's random() function
    // Make sure to seed the PRNG properly in setup() if using this.
    for (unsigned i = 0; i < size; ++i) {
      dest[i] = random(0, 256); // Generate a random byte
    }
    // A real implementation should check for errors and return 0 on failure
    return 1; // Return 1 to indicate success
  }

void setup()
{
  Serial.begin(115200); // Initialize serial communications with the PC

  // --- Seed the PRNG (IMPORTANT if using Arduino's random() in customRNG) ---
  // Use an unconnected analog pin for somewhat unpredictable seed.
  randomSeed(analogRead(A0)); // Use an unused analog pin (e.g., A0)

  lcd.init();
  lcd.backlight();
  setLCDMessageCentered("Starting up...", 0);
  SPI.begin();                       // Init SPI bus
  mfrc522.PCD_Init();                // Init MFRC522
  delay(4);                          // Optional delay. Some board do need more time after init to be ready, see Readme
  mfrc522.PCD_DumpVersionToSerial(); // Show details of PCD - MFRC522 Card Reader details
  Serial.println(F("Scan PICC to see UID, SAK, type, and data blocks..."));
  setLCDMessageCentered("Ready to scan", 0);
  delay(1000);

  // --- Set the RNG function for uECC ---
  uECC_set_rng(&customRNG);

  // --- Call generateKeys and store the returned struct ---
  // FIX 1: Corrected function call and assignment syntax
  EccKeyPair returnedKeys = generateKeys();

  Serial.println("\n--- Checking keys returned to setup() ---"); // Added separator

  // Check the success flag from the returned struct
  if (returnedKeys.success) {
    Serial.println("Key generation reported SUCCESS.");

    // Now, print the keys by accessing the arrays within the returned struct

    // Print the RETURNED Private Key
    Serial.println("Returned Private Key (accessed via struct):");
    for (size_t i = 0; i < sizeof(returnedKeys.privateKey); ++i) {
      if (returnedKeys.privateKey[i] < 16) {
        Serial.print("0"); // Add leading zero if needed
      }
      Serial.print(returnedKeys.privateKey[i], HEX);
    }
    Serial.println(); // Newline after the key

    // Print the RETURNED Public Key
    Serial.println("Returned Public Key (accessed via struct):");
    for (size_t i = 0; i < sizeof(returnedKeys.publicKey); ++i) {
      if (returnedKeys.publicKey[i] < 16) {
        Serial.print("0"); // Add leading zero if needed
      }
      Serial.print(returnedKeys.publicKey[i], HEX);
    }
    Serial.println(); // Newline after the key
  }
  else // Added else block for clarity
  {
      Serial.println("Key generation reported FAILURE.");
      // Consider adding error handling here - maybe halt execution?
      // while(1);
  }
   Serial.println("--- End of key check in setup() ---"); // Added separator
} // End of setup() function - Ensure this brace is present

void loop()
{
  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
  if (!mfrc522.PICC_IsNewCardPresent())
  {
    return;
  }

  // Select one of the cards
  if (!mfrc522.PICC_ReadCardSerial())
  {
    return;
  }

  // Dump debug info about the card; PICC_HaltA() is automatically called
  mfrc522.PICC_DumpToSerial(&(mfrc522.uid));
}

EccKeyPair generateKeys()
{
  // NOTE: RNG must be set via uECC_set_rng() before calling this function.

  EccKeyPair generatedKeys; // Create an instance of the struct to return
  generatedKeys.success = false; // Assume failure initially

  const struct uECC_Curve_t *curve = uECC_secp256r1();

  // Attempt to generate the keys directly into the struct's arrays
  if (!uECC_make_key(generatedKeys.publicKey, generatedKeys.privateKey, curve))
  {
    // Key generation failed
    Serial.println("Key generation failed!");
    // generatedKeys.success remains false
  }
  else
  {
    // Key generation successful
    // FIX 2: Added missing semicolon
    generatedKeys.success = true;
    // Optional: Add Serial prints here if you want generation messages too
    Serial.println("Key generation successful (within generateKeys).");
  }

  // FIX 3: Moved return statement outside the if/else block
  return generatedKeys; // Return the struct containing keys and success status
}

// Implementation of setLCDMessageCentered (seems okay, unchanged)
void setLCDMessageCentered(String message, int row)
{
  if (row < 0 || row >= lcdRows) { return; }
  int messageLen = message.length();
  String messageToDisplay = message;
  if (messageLen > lcdColumns) {
    messageToDisplay = messageToDisplay.substring(0, lcdColumns);
    messageLen = lcdColumns;
  }
  int totalEmptySpace = lcdColumns - messageLen;
  int leftPadding = totalEmptySpace / 2;
  String outputString = "";
  for (int i = 0; i < leftPadding; i++) { outputString += " "; }
  outputString += messageToDisplay;
  while (outputString.length() < lcdColumns) { outputString += " "; }
  lcd.setCursor(0, row);
  lcd.print(outputString);
}