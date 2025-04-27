#include <Arduino.h>
#include <LiquidCrystal_I2C.h>
#include <SPI.h>
#include <MFRC522.h>
#include <stdint.h> // Required for uint16_t

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
const int TOTAL_USER_AREA_SIZE = NUM_USER_DATA_BLOCKS * BLOCK_SIZE; // Should be 752 bytes

// --- Header Configuration ---
const byte HEADER_SIZE = 3; // 1 byte type + 2 bytes length
const int MAX_PAYLOAD_SIZE = TOTAL_USER_AREA_SIZE - HEADER_SIZE; // Max actual data size = 749 bytes

// --- Data Type Codes ---
const byte DATA_TYPE_NONE = 0x00;
const byte DATA_TYPE_PASSWORD = 0x01;
// Add more types here as needed (e.g., DATA_TYPE_NOTE = 0x02;)

// Define a default key (Key A) - Many cards use FFFFFFFFFFFFh as the default key A
MFRC522::MIFARE_Key key;

// Buffer to hold zero data (16 bytes)
byte zeroBuffer[BLOCK_SIZE] = {0}; // Initialize all elements to 0

// Function Prototypes
void setLCDMessageCentered(String message, int row);
bool authenticateBlock(byte blockAddr);
bool readBlockFromNfc(byte blockAddr, byte buffer[], byte bufferSize);
bool writeBlockToNfc(byte blockAddr, byte buffer[], byte bufferSize);
int readUserDataFromNfc(byte* dataType, uint16_t* dataLength, byte dataBuffer[], int bufferCapacity);
bool writeUserDataToNfc(byte dataType, byte payloadBuffer[], uint16_t payloadLength);
bool isUserDataBlock(byte blockAddr); // Helper to check if a block is in our user list
String getDataTypeName(byte dataType); // Helper to get string name for type code

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
  Serial.println(F("MIFARE Classic 1K User Data R/W (with Header)"));
  Serial.print(F("User Blocks: ")); Serial.println(NUM_USER_DATA_BLOCKS);
  Serial.print(F("Total User Area: ")); Serial.print(TOTAL_USER_AREA_SIZE); Serial.println(F(" bytes"));
  Serial.print(F("Header Size: ")); Serial.print(HEADER_SIZE); Serial.println(F(" bytes"));
  Serial.print(F("Max Payload: ")); Serial.print(MAX_PAYLOAD_SIZE); Serial.println(F(" bytes"));
  Serial.println(F("Scan card to read/write user data..."));
  setLCDMessageCentered("Ready to Scan", 0);
  setLCDMessageCentered("User Data+Hdr", 1);
  delay(1000);
}

void loop()
{
  // Look for new cards
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    delay(50);
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
  }

  // --- Example Operations ---

  // 1. Read Existing User Data (including header info)
  setLCDMessageCentered("Reading Card...", 0);
  setLCDMessageCentered("", 1);
  byte readDataType = DATA_TYPE_NONE;
  uint16_t readDataLength = 0;
  byte readPayloadBuffer[MAX_PAYLOAD_SIZE]; // Buffer for the actual payload

  int bytesRead = readUserDataFromNfc(&readDataType, &readDataLength, readPayloadBuffer, MAX_PAYLOAD_SIZE);

  if (bytesRead >= 0) {
    Serial.println(F("Read Successful:"));
    Serial.print(F("  Data Type: 0x")); Serial.print(readDataType, HEX);
    Serial.print(F(" (")); Serial.print(getDataTypeName(readDataType)); Serial.println(F(")"));
    Serial.print(F("  Payload Length: ")); Serial.println(readDataLength);
    Serial.print(F("  Bytes Copied: ")); Serial.println(bytesRead); // Should match readDataLength if buffer was large enough

    if (readDataLength > 0 && bytesRead > 0) {
        Serial.print(F("  Payload (Hex): "));
        for (int i = 0; i < min(bytesRead, 64); i++) { // Print first 64 bytes or less
            if (readPayloadBuffer[i] < 0x10) Serial.print(" 0"); else Serial.print(" ");
            Serial.print(readPayloadBuffer[i], HEX);
        }
        Serial.println();
        Serial.print(F("  Payload (ASCII): "));
        for (int i = 0; i < bytesRead; i++) { // Print all as ASCII
            if (isprint(readPayloadBuffer[i])) {
                Serial.print((char)readPayloadBuffer[i]);
            } else {
                Serial.print('.'); // Print dot for non-printable chars
            }
        }
        Serial.println();
    } else {
        Serial.println(F("  No payload data present or read."));
    }
    setLCDMessageCentered("Read OK", 1);
    delay(1000);

  } else {
    Serial.println(F("Failed to read user data. Error code: ")); Serial.println(bytesRead);
    setLCDMessageCentered("Read Failed!", 1);
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    delay(2000);
    setLCDMessageCentered("Ready to Scan", 0);
    setLCDMessageCentered("User Data+Hdr", 1);
    return; // Exit loop iteration on read failure
  }


  // 2. Prepare and Write New User Data (Password Example)
  setLCDMessageCentered("Writing Data...", 0);
  setLCDMessageCentered("", 1);

  // Example: Generate a simple pseudo-random password string
  String password = "Pwd_";
  for (int i = 0; i < 12; i++) { // Generate a 16-char password (Pwd_ + 12 random)
      char randomChar = random(33, 127); // Printable ASCII chars
      password += randomChar;
  }
  // Ensure length doesn't exceed max payload size
   if (password.length() > MAX_PAYLOAD_SIZE) {
       password = password.substring(0, MAX_PAYLOAD_SIZE);
   }

  byte passwordBytes[MAX_PAYLOAD_SIZE];
  uint16_t passwordLength = password.length();
  memcpy(passwordBytes, password.c_str(), passwordLength);

  Serial.print(F("Attempting to write Password ("));
  Serial.print(passwordLength); Serial.print(F(" bytes): "));
  Serial.println(password); // Be careful printing passwords in real applications!

  if (writeUserDataToNfc(DATA_TYPE_PASSWORD, passwordBytes, passwordLength)) {
    Serial.println(F("User data write successful (Header + Payload + Padding)."));
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
  setLCDMessageCentered("User Data+Hdr", 1);
}

// =========================================================================
// Helper Functions (authenticateBlock, isUserDataBlock, read/writeBlock remain similar)
// =========================================================================
/**
 * @brief Gets a string representation of the data type code.
 */
String getDataTypeName(byte dataType) {
    switch (dataType) {
        case DATA_TYPE_NONE: return "None/Empty";
        case DATA_TYPE_PASSWORD: return "Password";
        // Add cases for other types here
        default: return "Unknown";
    }
}

/**
 * @brief Checks if a block address is within the defined user data blocks.
 */
bool isUserDataBlock(byte blockAddr) {
    if (blockAddr >= NUM_TOTAL_BLOCKS) return false;
    if (blockAddr == 0 || (blockAddr + 1) % 4 == 0) return false;
    return true;
}

/**
 * @brief Authenticates a given block's sector using Key A.
 */
bool authenticateBlock(byte blockAddr) {
  if (blockAddr >= NUM_TOTAL_BLOCKS) return false;
  byte sector = blockAddr / 4;
  byte trailerBlock = sector * 4 + 3;
  MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Auth Error (Block ")); Serial.print(blockAddr); Serial.print(F("): ")); Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  return true;
}

/**
 * @brief Reads a single 16-byte block from the NFC card after authentication.
 */
bool readBlockFromNfc(byte blockAddr, byte buffer[], byte bufferSize) {
  if (bufferSize < 18) { Serial.println(F("Read buffer too small (<18)")); return false; }
  // We allow reading non-user blocks here (like trailers if needed elsewhere),
  // but the main readUserData function will only call this for user blocks.
  // Safety check is primarily in the calling function.

  if (!authenticateBlock(blockAddr)) return false;

  MFRC522::StatusCode status = mfrc522.MIFARE_Read(blockAddr, buffer, &bufferSize);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Read Error (Block ")); Serial.print(blockAddr); Serial.print(F("): ")); Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  return true;
}

/**
 * @brief Writes a single 16-byte block to the NFC card after authentication.
 */
bool writeBlockToNfc(byte blockAddr, byte buffer[], byte bufferSize) {
  if (bufferSize != BLOCK_SIZE) { Serial.print(F("Write Error: Buffer size must be ")); Serial.println(BLOCK_SIZE); return false; }
  if (!isUserDataBlock(blockAddr)) { Serial.print(F("Write Error: Attempt to write non-user block ")); Serial.println(blockAddr); return false; }

  if (!authenticateBlock(blockAddr)) return false;

  MFRC522::StatusCode status = mfrc522.MIFARE_Write(blockAddr, buffer, BLOCK_SIZE);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Write Error (Block ")); Serial.print(blockAddr); Serial.print(F("): ")); Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  return true;
}


// =========================================================================
// User Data Area Functions (with Header)
// =========================================================================

/**
 * @brief Reads the header and payload from the user data area.
 * Assumes card is present and selected. Handles authentication.
 * Stops crypto on failure.
 *
 * @param dataType Pointer to store the read data type code (output).
 * @param dataLength Pointer to store the read payload length from the header (output).
 * @param dataBuffer Buffer to store the actual payload data (output).
 * @param bufferCapacity The maximum size of dataBuffer.
 * @return The number of payload bytes successfully read and placed into dataBuffer (can be 0 if length in header is 0),
 * or -1 if the provided buffer is too small for the payload specified in the header,
 * or -2 if a read error occurred (e.g., auth failure, invalid header length),
 * or -3 if the first user block couldn't be read.
 */
int readUserDataFromNfc(byte* dataType, uint16_t* dataLength, byte dataBuffer[], int bufferCapacity) {
    byte firstBlockBuffer[18]; // Buffer for reading the first block (containing header)
    byte tempBlockBuffer[18];  // Buffer for reading subsequent blocks
    *dataType = DATA_TYPE_NONE; // Default to none
    *dataLength = 0;            // Default to zero length

    // 1. Read the first user data block
    byte firstUserBlockAddr = userDataBlocks[0]; // e.g., Block 1
    if (!readBlockFromNfc(firstUserBlockAddr, firstBlockBuffer, sizeof(firstBlockBuffer))) {
        Serial.println(F("Read User Data Error: Failed to read first user block (header block)."));
        mfrc522.PCD_StopCrypto1();
        return -3; // Indicate failure to read header block
    }

    // 2. Parse the header from the first block buffer
    *dataType = firstBlockBuffer[0];
    // Combine bytes 1 and 2 into uint16_t (assuming Little Endian for Arduino)
    *dataLength = (uint16_t)(firstBlockBuffer[2] << 8) | firstBlockBuffer[1];

    // 3. Validate the header data
    if (*dataLength > MAX_PAYLOAD_SIZE) {
        Serial.print(F("Read User Data Error: Header length (")); Serial.print(*dataLength);
        Serial.print(F(") exceeds max payload size (")); Serial.print(MAX_PAYLOAD_SIZE); Serial.println(F(")."));
        mfrc522.PCD_StopCrypto1();
        *dataLength = 0; // Reset length as it's invalid
        *dataType = DATA_TYPE_NONE; // Reset type
        return -2; // Indicate invalid header data
    }

    if (*dataLength == 0) {
        Serial.println(F("Read User Data: Header indicates zero payload length."));
        // No payload to read, but the read itself was successful.
        return 0; // Return 0 bytes read
    }

    if (*dataLength > bufferCapacity) {
        Serial.print(F("Read User Data Warning: Payload length (")); Serial.print(*dataLength);
        Serial.print(F(") exceeds provided buffer capacity (")); Serial.print(bufferCapacity); Serial.println(F(")."));
        // We can potentially still read the header info, but cannot return the payload.
        // Or we could return a specific error code. Let's return an error.
        mfrc522.PCD_StopCrypto1();
        return -1; // Indicate buffer too small
    }

    // 4. Read the actual payload data
    int bytesSuccessfullyRead = 0;
    int payloadBytesReadFromFirstBlock = 0;
    int payloadBytesToRead = *dataLength;

    // Copy payload bytes that were already read in the first block (after the header)
    payloadBytesReadFromFirstBlock = min((int)(BLOCK_SIZE - HEADER_SIZE), payloadBytesToRead);
    if (payloadBytesReadFromFirstBlock > 0) {
         memcpy(dataBuffer, firstBlockBuffer + HEADER_SIZE, payloadBytesReadFromFirstBlock);
         bytesSuccessfullyRead += payloadBytesReadFromFirstBlock;
    }


    // Read remaining payload bytes from subsequent user blocks
    int currentBlockIndex = 1; // Start from the second user data block
    while (bytesSuccessfullyRead < payloadBytesToRead && currentBlockIndex < NUM_USER_DATA_BLOCKS) {
        byte currentBlockAddr = userDataBlocks[currentBlockIndex];
        if (!readBlockFromNfc(currentBlockAddr, tempBlockBuffer, sizeof(tempBlockBuffer))) {
            Serial.print(F("Read User Data Error: Failed reading payload block ")); Serial.println(currentBlockAddr);
            mfrc522.PCD_StopCrypto1();
             *dataLength = 0; // Reset length as read failed
             *dataType = DATA_TYPE_NONE; // Reset type
            return -2; // Indicate read failure during payload read
        }

        int bytesToCopyFromThisBlock = min((int)BLOCK_SIZE, payloadBytesToRead - bytesSuccessfullyRead);
        memcpy(dataBuffer + bytesSuccessfullyRead, tempBlockBuffer, bytesToCopyFromThisBlock);
        bytesSuccessfullyRead += bytesToCopyFromThisBlock;
        currentBlockIndex++;
         delay(10); // Small delay
    }

    // Check if we read the expected number of bytes
    if (bytesSuccessfullyRead != payloadBytesToRead) {
         Serial.print(F("Read User Data Error: Mismatch between header length (")); Serial.print(payloadBytesToRead);
         Serial.print(F(") and bytes read (")); Serial.print(bytesSuccessfullyRead); Serial.println(F(")."));
         mfrc522.PCD_StopCrypto1();
         *dataLength = 0; // Reset length as read failed
         *dataType = DATA_TYPE_NONE; // Reset type
         return -2; // Indicate read failure (length mismatch)
    }

    // Success!
    return bytesSuccessfullyRead;
}


/**
 * @brief Writes a header and payload to the user data area.
 * Pads the last payload block and zeros out remaining user blocks.
 * Assumes card is present and selected. Handles authentication.
 * Stops crypto on failure.
 *
 * @param dataType The data type code to write in the header.
 * @param payloadBuffer Buffer containing the payload data to write.
 * @param payloadLength The number of bytes in payloadBuffer to write. Max MAX_PAYLOAD_SIZE.
 * @return true if all writes (header, payload, padding, zeroing) were successful, false otherwise.
 */
bool writeUserDataToNfc(byte dataType, byte payloadBuffer[], uint16_t payloadLength) {
    if (payloadLength > MAX_PAYLOAD_SIZE) {
        Serial.print(F("Write User Data Error: Payload length (")); Serial.print(payloadLength);
        Serial.print(F(") exceeds max size (")); Serial.print(MAX_PAYLOAD_SIZE); Serial.println(F(")."));
        return false;
    }

    byte tempBlockBuffer[BLOCK_SIZE];
    bool success = true;
    int totalBytesToWrite = HEADER_SIZE + payloadLength;
    // Calculate total user blocks needed (including the one starting with the header)
    int blocksNeeded = (totalBytesToWrite + BLOCK_SIZE - 1) / BLOCK_SIZE;

    int payloadBytesWritten = 0;

    // --- Write blocks containing header and payload data ---
    for (int i = 0; i < blocksNeeded; i++) {
        byte currentBlockAddr = userDataBlocks[i];
        memset(tempBlockBuffer, 0, BLOCK_SIZE); // Start with a zeroed buffer for padding

        int bytesToCopyInThisBlock = 0;

        // Handle the first block (header + start of payload)
        if (i == 0) {
            // Write header
            tempBlockBuffer[0] = dataType;
            tempBlockBuffer[1] = (byte)(payloadLength & 0xFF);         // Low byte of length
            tempBlockBuffer[2] = (byte)((payloadLength >> 8) & 0xFF); // High byte of length

            // Copy first part of payload into the rest of the first block
            bytesToCopyInThisBlock = min((int)(BLOCK_SIZE - HEADER_SIZE), (int)payloadLength);
            if (bytesToCopyInThisBlock > 0) {
                 memcpy(tempBlockBuffer + HEADER_SIZE, payloadBuffer, bytesToCopyInThisBlock);
                 payloadBytesWritten += bytesToCopyInThisBlock;
            }
        }
        // Handle subsequent payload blocks
        else {
            int remainingPayload = payloadLength - payloadBytesWritten;
            bytesToCopyInThisBlock = min((int)BLOCK_SIZE, remainingPayload);
             if (bytesToCopyInThisBlock > 0) {
                memcpy(tempBlockBuffer, payloadBuffer + payloadBytesWritten, bytesToCopyInThisBlock);
                payloadBytesWritten += bytesToCopyInThisBlock;
             }
             // The rest of tempBlockBuffer is already zeroed (padding)
        }

        // Write the prepared block buffer to the card
        if (!writeBlockToNfc(currentBlockAddr, tempBlockBuffer, BLOCK_SIZE)) {
            Serial.print(F("Write User Data Error: Failed writing block ")); Serial.println(currentBlockAddr);
            success = false;
            break; // Stop writing if an error occurs
        }
         delay(20); // Write delay
    }

    // --- Zero out remaining user data blocks (if write was successful so far) ---
    if (success) {
        Serial.print(F("Payload write phase complete. Zeroing remaining "));
        Serial.print(NUM_USER_DATA_BLOCKS - blocksNeeded);
        Serial.println(F(" user blocks..."));
        for (int i = blocksNeeded; i < NUM_USER_DATA_BLOCKS; i++) {
             byte currentBlockAddr = userDataBlocks[i];
             // Use the global zeroBuffer for efficiency
             if (!writeBlockToNfc(currentBlockAddr, zeroBuffer, BLOCK_SIZE)) {
                 Serial.print(F("Write User Data Error: Failed zeroing block ")); Serial.println(currentBlockAddr);
                 success = false;
                 break; // Stop zeroing if an error occurs
             }
              delay(20); // Write delay
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
void setLCDMessageCentered(String message, int row) {
    if (row < 0 || row >= lcdRows) { return; }
    int messageLen = message.length();
    String messageToDisplay = message;
    if (messageLen > lcdColumns) { messageToDisplay = messageToDisplay.substring(0, lcdColumns); messageLen = lcdColumns; }
    int totalEmptySpace = lcdColumns - messageLen;
    int leftPadding = totalEmptySpace / 2;
    String outputString = "";
    for (int i = 0; i < leftPadding; i++) { outputString += " "; }
    outputString += messageToDisplay;
    while (outputString.length() < lcdColumns) { outputString += " "; }
    lcd.setCursor(0, row);
    lcd.print(outputString);
}
