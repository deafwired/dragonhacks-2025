#include <SPI.h>
#include <MFRC522.h>

// Define pins (adjust if needed)
#define SS_PIN 10  // SDA (SS) pin on the MFRC522 module
#define RST_PIN 9  // RST pin on the MFRC522 module

MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance

void setup() {
  Serial.begin(115200); // Start Serial Monitor
  SPI.begin();          // Start SPI bus
  mfrc522.PCD_Init();   // Initialize MFRC522 reader

  Serial.println("Approach your NFC/RFID card to the reader...");
}

void loop() {
  // Look for a new card
  if (!mfrc522.PICC_IsNewCardPresent()) {
    return; // No card, just loop
  }

  // Select one of the cards
  if (!mfrc522.PICC_ReadCardSerial()) {
    return; // Failed to read card
  }

  // Card detected and data read
  Serial.print("Card UID: ");
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX); // Print in hexadecimal
  }
  Serial.println();

  Serial.print("Card SAK: ");
  Serial.println(mfrc522.uid.sak, HEX); // SAK is Select Acknowledge (card type info)

  // Halt the card to stop communication until next read
  mfrc522.PICC_HaltA();
}