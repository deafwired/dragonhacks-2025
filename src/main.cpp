#include <Arduino.h>
#include <LiquidCrystal_I2C.h>
#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN 5 // Configurable, adjust to your setup
#define SS_PIN 53 // Configurable, adjust to your setup

MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance

const int lcdColumns = 16;
const int lcdRows = 2;
LiquidCrystal_I2C lcd(0x27, lcdColumns, lcdRows); // Set the LCD address (0x27 is common)

// --- MIFARE Classic 1K Configuration ---
const byte NUM_TOTAL_BLOCKS = 64;
const byte BLOCK_SIZE = 16; // Bytes per block
// Define the blocks available for user data (skipping block 0 and sector trailers)
const byte userDataBlocks[] = {
     1,  2,      4,  5,  6,      8,  9, 10,     12, 13, 14,     // Sectors 0-3
    16, 17, 18,     20, 21, 22,     24, 25, 26,     28, 29, 30,     // Sectors 4-7
    32, 33, 34,     36, 37, 38,     40, 41, 42,     44, 45, 46,     // Sectors 8-11
    48, 49, 50,     52, 53, 54,     56, 57, 58,     60, 61, 62      // Sectors 12-15
};
const int NUM_USER_DATA_BLOCKS = sizeof(userDataBlocks) / sizeof(userDataBlocks[0]); // Should be 47
const int MAX_USER_DATA_SIZE = NUM_USER_DATA_BLOCKS * BLOCK_SIZE; // Should be 752 bytes

// Define a default key (Key A) - Many cards use FFFFFFFFFFFFh as the default key A
MFRC522::MIFARE_Key key;

// Buffer to hold zero data (16 bytes)
byte zeroBuffer[BLOCK_SIZE] = {0}; // Initialize all elements to 0

// Function Prototypes
void setLCDMessageCentered(String message, int row);
bool authenticateBlock(byte blockAddr);
bool readBlockFromNfc(byte blockAddr, byte buffer[], byte bufferSize);
bool writeBlockToNfc(byte blockAddr, byte buffer[], byte bufferSize);
int readUserDataFromNfc(byte dataBuffer[], int bufferCapacity);
bool writeUserDataToNfc(byte dataBuffer[], int dataLength);
bool isUserDataBlock(byte blockAddr); // Helper to check if a block is in our user list

void setup()
{
  Serial.begin(115200);
  while (!Serial);

  lcd.init();
  lcd.backlight();
  setLCDMessageCentered("Starting up...", 0);
  Serial.println("LCD Initialized.");

  SPI.begin();
  mfrc522.PCD_Init();
  delay(4);
  Serial.println("MFRC522 Initialized.");
  mfrc522.PCD_DumpVersionToSerial();

  // Prepare the default key A (FF FF FF FF FF FF)
  // *** CHANGE THIS IF YOUR CARD USES A DIFFERENT KEY ***
  for (byte i = 0; i < 6; i++) {
      key.keyByte[i] = 0xFF;
  }

  Serial.println(F("-----------------------"));
  Serial.println(F("MIFARE Classic 1K User Data R/W"));
  Serial.print(F("User Blocks: ")); Serial.println(NUM_USER_DATA_BLOCKS);
  Serial.print(F("Max User Data: ")); Serial.print(MAX_USER_DATA_SIZE); Serial.println(F(" bytes"));
  Serial.println(F("Scan card to read/write user data..."));
  setLCDMessageCentered("Ready to Scan", 0);
  setLCDMessageCentered("User Data Mode", 1);
  delay(1000);
}

void loop()
{
  // Look for new cards
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    // No card or read failed, clear LCD row 1 and wait
    // setLCDMessageCentered("", 1); // Optional: clear status line when no card
    delay(50); // Small delay to prevent busy-waiting
    return;
  }

  // --- Card Found ---
  Serial.println(F("-----------------------"));
  Serial.print(F("Card Found! UID:"));
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }
  Serial.println();
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.print(F("PICC type: ")); Serial.println(mfrc522.PICC_GetTypeName(piccType));

  // Optional: Check if it's a compatible type
   if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI &&
      piccType != MFRC522::PICC_TYPE_MIFARE_1K &&
      piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
      Serial.println(F("Warning: Card may not be MIFARE Classic compatible."));
      // Decide if you want to proceed or stop here
  }

  // --- Example Operations ---

  // 1. Read Existing User Data
  setLCDMessageCentered("Reading Card...", 0);
  setLCDMessageCentered("", 1);
  byte readBuffer[MAX_USER_DATA_SIZE];
  int bytesRead = readUserDataFromNfc(readBuffer, MAX_USER_DATA_SIZE);

  if (bytesRead >= 0) {
    Serial.print(F("Successfully read ")); Serial.print(bytesRead); Serial.println(F(" bytes of user data:"));
    // Print the read data (e.g., first 64 bytes)
    Serial.print(F("Data (Hex): "));
    for (int i = 0; i < min(bytesRead, 64); i++) { // Print first 64 bytes or less
        if (readBuffer[i] < 0x10) Serial.print(" 0"); else Serial.print(" ");
        Serial.print(readBuffer[i], HEX);
    }
    Serial.println();
     Serial.print(F("Data (ASCII): "));
    for (int i = 0; i < bytesRead; i++) { // Print all as ASCII
        if (isprint(readBuffer[i])) {
            Serial.print((char)readBuffer[i]);
        } else {
            Serial.print('.'); // Print dot for non-printable chars
        }
    }
    Serial.println();
    setLCDMessageCentered("Read Success!", 1);
    delay(1000); // Show success message

  } else {
    Serial.println(F("Failed to read user data."));
    setLCDMessageCentered("Read Failed!", 1);
    // Halt card and stop crypto before returning
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    delay(2000);
    setLCDMessageCentered("Ready to Scan", 0); // Reset LCD for next scan
    setLCDMessageCentered("User Data Mode", 1);
    return; // Exit loop iteration on read failure
  }


  // 2. Prepare and Write New User Data
  setLCDMessageCentered("Writing Data...", 0);
  setLCDMessageCentered("", 1);
  // Example: Write a string. Remember MAX_USER_DATA_SIZE limit (752 bytes)
  String userDataString = "Hello from Arduino! Time: " + String(millis());
  byte dataToWrite[MAX_USER_DATA_SIZE]; // Use a buffer large enough
  int dataLength = userDataString.length();

  // Clamp data length if it exceeds max size
  if (dataLength > MAX_USER_DATA_SIZE) {
      dataLength = MAX_USER_DATA_SIZE;
      Serial.println("Warning: User data truncated to fit card capacity.");
  }

  // Copy string bytes to the buffer
  memcpy(dataToWrite, userDataString.c_str(), dataLength);

  Serial.print(F("Attempting to write ")); Serial.print(dataLength); Serial.println(F(" bytes of user data..."));

  if (writeUserDataToNfc(dataToWrite, dataLength)) {
    Serial.println(F("User data write successful (including zero-padding)."));
    setLCDMessageCentered("Write Success!", 1);
  } else {
    Serial.println(F("User data write failed."));
    setLCDMessageCentered("Write Failed!", 1);
  }

  // --- Cleanup for this card ---
  mfrc522.PICC_HaltA();       // Halt PICC
  mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD

  Serial.println(F("Card released. Waiting for next card..."));
  delay(3000); // Pause before next scan attempt
  setLCDMessageCentered("Ready to Scan", 0);
  setLCDMessageCentered("User Data Mode", 1);
}

// =========================================================================
// Helper Functions
// =========================================================================

bool isUserDataBlock(byte blockAddr) {
    // Check bounds first (although loop in read/write uses the array directly)
    if (blockAddr >= NUM_TOTAL_BLOCKS) return false;
    // Check block 0 and sector trailers
    if (blockAddr == 0 || (blockAddr + 1) % 4 == 0) return false;
    // Could also iterate through userDataBlocks array for certainty, but this is faster
    return true;
}

bool authenticateBlock(byte blockAddr) {
  if (blockAddr >= NUM_TOTAL_BLOCKS) return false; // Invalid block

  byte sector = blockAddr / 4;
  byte trailerBlock = sector * 4 + 3;

  MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Auth Error (Block ")); Serial.print(blockAddr);
    Serial.print(F(", Sector ")); Serial.print(sector);
    Serial.print(F("): ")); Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  return true;
}

bool readBlockFromNfc(byte blockAddr, byte buffer[], byte bufferSize) {
  if (bufferSize < 18) {
      Serial.println(F("Read buffer too small (<18)"));
      return false;
  }
   if (!isUserDataBlock(blockAddr)) { // Safety check
      Serial.print(F("Read Error: Attempt to read non-user block ")); Serial.println(blockAddr);
      return false;
  }

  // Authenticate the sector for this block
  if (!authenticateBlock(blockAddr)) {
    return false; // Authentication failed
  }

  // Read the block
  MFRC522::StatusCode status = mfrc522.MIFARE_Read(blockAddr, buffer, &bufferSize); // bufferSize is updated by the call

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Read Error (Block ")); Serial.print(blockAddr);
    Serial.print(F("): ")); Serial.println(mfrc522.GetStatusCodeName(status));
    // Don't stop crypto here, let the main operation handler do it
    return false;
  }
  // Success
  return true;
}

bool writeBlockToNfc(byte blockAddr, byte buffer[], byte bufferSize) {
  if (bufferSize != BLOCK_SIZE) {
    Serial.print(F("Write Error: Buffer size must be ")); Serial.println(BLOCK_SIZE);
    return false;
  }
  if (!isUserDataBlock(blockAddr)) { // Safety check
      Serial.print(F("Write Error: Attempt to write non-user block ")); Serial.println(blockAddr);
      return false;
  }

  // Authenticate the sector for this block
  if (!authenticateBlock(blockAddr)) {
    return false; // Authentication failed
  }

  // Write the block
  MFRC522::StatusCode status = mfrc522.MIFARE_Write(blockAddr, buffer, BLOCK_SIZE);

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Write Error (Block ")); Serial.print(blockAddr);
    Serial.print(F("): ")); Serial.println(mfrc522.GetStatusCodeName(status));
    // Don't stop crypto here, let the main operation handler do it
    return false;
  }
  // Success
  return true;
}


// =========================================================================
// User Data Area Functions
// =========================================================================

int readUserDataFromNfc(byte dataBuffer[], int bufferCapacity) {
    if (bufferCapacity < MAX_USER_DATA_SIZE) {
        Serial.println(F("Read User Data Error: Provided buffer too small."));
        return -1; // Indicate buffer too small
    }

    byte tempBlockBuffer[18]; // Buffer for single block read (needs 18 bytes)
    int bytesSuccessfullyRead = 0;

    // Iterate through the defined user data blocks
    for (int i = 0; i < NUM_USER_DATA_BLOCKS; i++) {
        byte currentBlockAddr = userDataBlocks[i];

        // Read the current user data block
        if (readBlockFromNfc(currentBlockAddr, tempBlockBuffer, sizeof(tempBlockBuffer))) {
            // Copy the 16 data bytes from the temp buffer to the main dataBuffer
            memcpy(dataBuffer + (i * BLOCK_SIZE), tempBlockBuffer, BLOCK_SIZE);
            bytesSuccessfullyRead += BLOCK_SIZE;
        } else {
            // Read failed for this block
            Serial.print(F("Read User Data Error: Failed reading block ")); Serial.println(currentBlockAddr);
            mfrc522.PCD_StopCrypto1(); // Stop crypto since we failed mid-operation
            return -2; // Indicate read failure
        }
         delay(10); // Small delay between block reads can improve stability
    }

    // If we reached here, all user blocks were read successfully
    // Authentication might still be active, caller should handle HaltA and StopCrypto1
    return bytesSuccessfullyRead; // Should equal MAX_USER_DATA_SIZE
}

bool writeUserDataToNfc(byte dataBuffer[], int dataLength) {
    if (dataLength < 0 || dataLength > MAX_USER_DATA_SIZE) {
        Serial.print(F("Write User Data Error: Invalid data length ("));
        Serial.print(dataLength); Serial.println(F(")."));
        return false;
    }

    byte tempBlockBuffer[BLOCK_SIZE];
    int blocksToWrite = (dataLength + BLOCK_SIZE - 1) / BLOCK_SIZE; // Ceiling division
    bool success = true;

    // --- Write the actual user data ---
    for (int i = 0; i < blocksToWrite; i++) {
        byte currentBlockAddr = userDataBlocks[i];
        int currentDataOffset = i * BLOCK_SIZE;
        int bytesToCopy = BLOCK_SIZE;

        // For the last block, only copy remaining bytes and pad with zero
        if (i == blocksToWrite - 1) {
            bytesToCopy = dataLength - currentDataOffset;
            // Copy the remaining data
            memcpy(tempBlockBuffer, dataBuffer + currentDataOffset, bytesToCopy);
            // Pad the rest of the block buffer with zeros
            memset(tempBlockBuffer + bytesToCopy, 0, BLOCK_SIZE - bytesToCopy);
        } else {
            // Copy a full block of data
            memcpy(tempBlockBuffer, dataBuffer + currentDataOffset, BLOCK_SIZE);
        }

        // Write the prepared block buffer to the card
        if (!writeBlockToNfc(currentBlockAddr, tempBlockBuffer, BLOCK_SIZE)) {
            Serial.print(F("Write User Data Error: Failed writing block ")); Serial.println(currentBlockAddr);
            success = false;
            break; // Stop writing if an error occurs
        }
         delay(20); // Slightly longer delay for writes might help
    }

    // --- Zero out remaining user data blocks (if write was successful so far) ---
    if (success) {
        Serial.print(F("Data write phase complete. Zeroing remaining "));
        Serial.print(NUM_USER_DATA_BLOCKS - blocksToWrite);
        Serial.println(F(" user blocks..."));
        for (int i = blocksToWrite; i < NUM_USER_DATA_BLOCKS; i++) {
             byte currentBlockAddr = userDataBlocks[i];
             if (!writeBlockToNfc(currentBlockAddr, zeroBuffer, BLOCK_SIZE)) {
                 Serial.print(F("Write User Data Error: Failed zeroing block ")); Serial.println(currentBlockAddr);
                 success = false;
                 break; // Stop zeroing if an error occurs
             }
              delay(20);
        }
    }

    // If any part failed, stop crypto here
    if (!success) {
        mfrc522.PCD_StopCrypto1();
    }

    // Caller should handle HaltA and StopCrypto1 on success
    return success;
}


// Implementation of setLCDMessageCentered (remains the same)
void setLCDMessageCentered(String message, int row)
{
  if (row < 0 || row >= lcdRows) { return; } // Basic bounds check
  int messageLen = message.length();
  String messageToDisplay = message;

  // Truncate if message is too long
  if (messageLen > lcdColumns) {
    messageToDisplay = messageToDisplay.substring(0, lcdColumns);
    messageLen = lcdColumns;
  }

  // Calculate padding
  int totalEmptySpace = lcdColumns - messageLen;
  int leftPadding = totalEmptySpace / 2; // Integer division handles centering

  // Build the output string with padding
  String outputString = "";
  for (int i = 0; i < leftPadding; i++) {
    outputString += " ";
  }
  outputString += messageToDisplay;

  // Pad remaining space on the right (optional, but ensures clearing old text)
  while (outputString.length() < lcdColumns) {
    outputString += " ";
  }

  // Set cursor and print
  lcd.setCursor(0, row);
  lcd.print(outputString);
}
