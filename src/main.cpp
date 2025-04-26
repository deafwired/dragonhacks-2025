#include <Arduino.h>
#include <LiquidCrystal_I2C.h>
#include <SPI.h>
#include <MFRC522.h>
#include <uECC.h>
#include <String.h>

#define RST_PIN 5 // Configurable, see typical pin layout above
#define SS_PIN 53 // Configurable, see typical pin layout above

MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance

const int lcdColumns = 16;
const int lcdRows = 2;
LiquidCrystal_I2C lcd(0x27, lcdColumns, lcdRows);
void setLCDMessageCentered(String message, int row);

void setup()
{
  Serial.begin(115200); // Initialize serial communications with the PC
  // while (!Serial);  // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
  lcd.init();
  lcd.backlight();
  setLCDMessageCentered("Starting up...", 0);
  SPI.begin();                       // Init SPI bus
  mfrc522.PCD_Init();                // Init MFRC522
  delay(4);                          // Optional delay. Some board do need more time after init to be ready, see Readme
  mfrc522.PCD_DumpVersionToSerial(); // Show details of PCD - MFRC522 Card Reader details
  Serial.println(F("Scan PICC to see UID, SAK, type, and data blocks..."));
  setLCDMessageCentered("Ready to scan", 0);
}

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

uint8_t[] generateKeys()
{
  uint8_t privateKey[32];
  uint8_t publicKey[64];

  const struct uECC_Curve_t *curve = uECC_secp256r1();

  if (!uECC_make_key(publicKey, privateKey, curve))
  {
    Serial.println("Key generation failed!");
    return;
  }

  Serial.println("Private Key:");
  for (size_t i = 0; i < sizeof(privateKey); ++i)
  {
    if (privateKey[i] < 16)
      Serial.print("0");
    Serial.print(privateKey[i], HEX);
  }
  Serial.println();

  Serial.println("Public Key:");
  for (size_t i = 0; i < sizeof(publicKey); ++i)
  {
    if (publicKey[i] < 16)
      Serial.print("0");
    Serial.print(publicKey[i], HEX);
  }
  Serial.println();
  return [ privateKey, publicKey ];
}

void setLCDMessageCentered(String message, int row)
{
  // 1. Validate the target row number
  if (row < 0 || row >= lcdRows)
  {
    // Invalid row, optionally print an error to Serial monitor if available
    // Serial.print("Error: Invalid LCD row "); Serial.println(row);
    return; // Exit the function if the row is invalid
  }

  // 2. Prepare the message content
  int messageLen = message.length();
  String messageToDisplay = message; // Use a copy to potentially modify

  // Truncate the message if it's longer than the LCD width
  if (messageLen > lcdColumns)
  {
    messageToDisplay = messageToDisplay.substring(0, lcdColumns);
    messageLen = lcdColumns; // Update the length after truncation
  }

  // 3. Calculate the necessary padding for centering
  int totalEmptySpace = lcdColumns - messageLen;
  int leftPadding = totalEmptySpace / 2; // Integer division handles the floor

  // 4. Build the final string with padding
  String outputString = "";
  // Add spaces for left padding
  for (int i = 0; i < leftPadding; i++)
  {
    outputString += " ";
  }
  // Add the actual message (which might have been truncated)
  outputString += messageToDisplay;
  // Add spaces for right padding to fill the remaining columns
  while (outputString.length() < lcdColumns)
  {
    outputString += " ";
  }

  // 5. Display the centered message on the LCD
  lcd.setCursor(0, row);   // Move cursor to the start of the specified row
  lcd.print(outputString); // Print the fully padded and centered string
}