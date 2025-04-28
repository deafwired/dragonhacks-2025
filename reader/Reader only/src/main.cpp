/*
 * --------------------------------------------------------------------------------------------------------------------
 * Example sketch to read ASCII data from specific blocks of a MIFARE Classic 1K card,
 * assuming the data format written by the "NFC Password Manager" script. (Corrected Version)
 * --------------------------------------------------------------------------------------------------------------------
 * Reads data sequentially from blocks defined in `userDataBlocks`, skipping the header.
 * Uses default Key A (0xFFFFFFFFFFFF) for authentication.
 * Prints the payload data as ASCII characters to the Serial Monitor.
 * @license Released into the public domain.
 *
 * Pinout based on common setups (adjust for your board):
 * MFRC522      Arduino Mega    Arduino Uno
 * RST/Reset    D5              D9
 * SPI SS       D53             D10
 * SPI MOSI     D51             D11
 * SPI MISO     D50             D12
 * SPI SCK      D52             D13
 */

 #include <SPI.h>
 #include <MFRC522.h>
 #include <Arduino.h> // Include Arduino core for min()
 
 // --- Pin Definitions (Using Arduino Mega defaults) ---
 #define RST_PIN 5   // Configurable, adjust to your setup
 #define SS_PIN 53  // Configurable, adjust to your setup (Mega: 53, Uno: 10)
 
 // --- Component Initialization ---
 MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance
 
 // --- MIFARE Classic 1K Configuration (Copied from Password Manager Script) ---
 const byte NUM_TOTAL_BLOCKS = 64;
 const byte BLOCK_SIZE = 16;
 const byte userDataBlocks[] = {
      1,  2,      4,  5,  6,      8,  9, 10,     12, 13, 14,     // Sectors 0-3
     16, 17, 18,     20, 21, 22,     24, 25, 26,     28, 29, 30,     // Sectors 4-7
     32, 33, 34,     36, 37, 38,     40, 41, 42,     44, 45, 46,     // Sectors 8-11
     48, 49, 50,     52, 53, 54,     56, 57, 58,     60, 61, 62      // Sectors 12-15
 };
 // Using int for NUM_USER_DATA_BLOCKS derived from sizeof is okay
 const int NUM_USER_DATA_BLOCKS = sizeof(userDataBlocks) / sizeof(userDataBlocks[0]);
 const byte HEADER_SIZE = 3; // 1 byte type + 2 bytes length
 // MAX_PAYLOAD_SIZE can be int, its value won't overflow standard int
 const int MAX_PAYLOAD_SIZE = (NUM_USER_DATA_BLOCKS * BLOCK_SIZE) - HEADER_SIZE; // Max possible payload
 
 // --- NFC Key ---
 MFRC522::MIFARE_Key key; // Default Key A (set in setup)
 
 // --- Helper Function Prototypes ---
 bool authenticateBlock(byte blockAddr);
 bool readBlockFromNfc(byte blockAddr, byte buffer[], byte bufferSize);
 
 
 // =========================================================================
 // Setup
 // =========================================================================
 void setup() {
     Serial.begin(115200);
     while (!Serial); // Wait for Serial Monitor connection (needed for some boards)
 
     Serial.println(F("ASCII NFC Card Reader (Corrected)"));
     Serial.println(F("Reads data based on 'Password Manager' script format."));
     Serial.println(F("--------------------------------------------------"));
 
     SPI.begin();          // Init SPI bus
     mfrc522.PCD_Init();   // Init MFRC522 reader
     delay(4);             // Optional delay, helps prevent issues on some boards
     mfrc522.PCD_DumpVersionToSerial(); // Show reader details
 
     // Set the default MIFARE Key A (all FFs)
     for (byte i = 0; i < 6; i++) {
         key.keyByte[i] = 0xFF;
     }
     Serial.println(F("Using Default Key A (0xFFFFFFFFFFFF)"));
     Serial.println(F("Scan a card..."));
     Serial.println();
 }
 
 // =========================================================================
 // Main Loop
 // =========================================================================
 void loop() {
     // Look for new cards
     if (!mfrc522.PICC_IsNewCardPresent()) {
         delay(50); // Small delay to avoid busy-waiting
         return;
     }
 
     // Select one of the cards
     if (!mfrc522.PICC_ReadCardSerial()) {
         Serial.println(F("Card selection failed. Please remove and retry."));
         delay(1000);
         return;
     }
 
     // --- Card Selected ---
     Serial.println(F("*************************** CARD DETECTED ***************************"));
 
     // Print UID
     Serial.print(F("Card UID:"));
     for (byte i = 0; i < mfrc522.uid.size; i++) {
         Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
         Serial.print(mfrc522.uid.uidByte[i], HEX);
     }
     Serial.println();
 
     // Print PICC type
     MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
     Serial.print(F("PICC type: "));
     Serial.println(mfrc522.PICC_GetTypeName(piccType));
 
     // Check if it's a MIFARE Classic card (the password manager targeted these)
     if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI &&
         piccType != MFRC522::PICC_TYPE_MIFARE_1K &&
         piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
         Serial.println(F("Warning: Card is not MIFARE Classic. Data structure might differ."));
         // Continue anyway, but the read might fail or be incorrect
     }
 
     // --- Attempt to read the data ---
     byte firstBlockBuffer[18]; // Buffer for reading the first block (needs 18 bytes for MIFARE_Read)
     byte tempBlockBuffer[18]; // Buffer for reading subsequent blocks
     uint16_t storedPayloadLength = 0; // Use uint16_t for length
     byte firstUserBlockAddr = userDataBlocks[0]; // Should be block 1
 
     Serial.println(F("Attempting to read header from first user block..."));
 
     // Authenticate the sector containing the first user block (Sector 0 for block 1)
     if (!authenticateBlock(firstUserBlockAddr)) {
         Serial.println(F("Authentication failed for sector 0. Cannot read header."));
         mfrc522.PICC_HaltA(); // Halt the card
         mfrc522.PCD_StopCrypto1(); // Stop encryption on reader
         Serial.println(F("*********************************************************************"));
         Serial.println();
         delay(2000); // Wait before next scan attempt
         return;
     }
 
     // Read the first user block containing the header
     byte readBufferSize = sizeof(firstBlockBuffer);
     if (!readBlockFromNfc(firstUserBlockAddr, firstBlockBuffer, readBufferSize)) {
         Serial.println(F("Failed to read the first user block (header block)."));
         mfrc522.PICC_HaltA();
         mfrc522.PCD_StopCrypto1();
         Serial.println(F("*********************************************************************"));
         Serial.println();
         delay(2000);
         return;
     }
 
     // Parse the header to get the payload length (ignore data type byte 0)
     // Length is stored Little Endian (LSB first) in bytes 1 and 2
     storedPayloadLength = (uint16_t)(firstBlockBuffer[2] << 8) | firstBlockBuffer[1];
 
     Serial.print(F("Header Found: Type=0x")); Serial.print(firstBlockBuffer[0], HEX);
     Serial.print(F(", Stored Payload Length=")); Serial.println(storedPayloadLength);
 
     // Basic validation of length - compare uint16_t with int MAX_PAYLOAD_SIZE (okay)
     if (storedPayloadLength > MAX_PAYLOAD_SIZE) {
         Serial.print(F("Error: Stored length (")); Serial.print(storedPayloadLength);
         Serial.print(F(") exceeds maximum possible payload size (")); Serial.print(MAX_PAYLOAD_SIZE); Serial.println(F(")."));
         mfrc522.PICC_HaltA();
         mfrc522.PCD_StopCrypto1();
         Serial.println(F("*********************************************************************"));
         Serial.println();
         delay(2000);
         return;
     }
 
     if (storedPayloadLength == 0) {
         Serial.println(F("Stored payload length is 0. No data to display."));
     } else {
         Serial.println(F("--- Reading Payload Data as ASCII ---"));
 
         // CORRECTED: Change bytesPrinted to uint16_t
         uint16_t bytesPrinted = 0;
         // ADDED: Declare the success flag
         bool success = true;
         byte lastAuthenticatedSector = 0; // Sector 0 was authenticated for header read
 
         // Print payload data from the first block (bytes after the header)
         // CORRECTED: Use uint16_t for comparison in min()
         uint16_t bytesToPrintFromFirstBlock = min((uint16_t)(BLOCK_SIZE - HEADER_SIZE), storedPayloadLength);
         for (uint16_t i = 0; i < bytesToPrintFromFirstBlock; i++) { // Also use uint16_t for loop counter
             if (isprint(firstBlockBuffer[HEADER_SIZE + i])) {
                  Serial.print((char)firstBlockBuffer[HEADER_SIZE + i]);
             } else {
                  Serial.print('.'); // Replace non-printable chars with a dot
             }
             bytesPrinted++;
         }
 
         // Read and print data from subsequent user data blocks
         // CORRECTED: Loop condition compares uint16_t with uint16_t
         for (int blockIndex = 1; blockIndex < NUM_USER_DATA_BLOCKS && bytesPrinted < storedPayloadLength; blockIndex++) {
             byte currentBlockAddr = userDataBlocks[blockIndex];
             byte currentSector = currentBlockAddr / 4;
 
             // Authenticate if we've moved to a new sector
             if (currentSector != lastAuthenticatedSector) {
                  Serial.print(F("\nAuthenticating Sector ")); Serial.print(currentSector); Serial.println("...");
                  if (!authenticateBlock(currentBlockAddr)) {
                     Serial.print(F("Authentication failed for Sector ")); Serial.println(currentSector);
                     Serial.println(F("Stopping read. Displayed data might be incomplete."));
                     success = false; // Mark as incomplete - This line is now valid
                     break; // Stop reading blocks
                  }
                  lastAuthenticatedSector = currentSector;
             }
 
             // Read the current block
             readBufferSize = sizeof(tempBlockBuffer);
             if (!readBlockFromNfc(currentBlockAddr, tempBlockBuffer, readBufferSize)) {
                  Serial.print(F("Failed to read block ")); Serial.println(currentBlockAddr);
                  Serial.println(F("Stopping read. Displayed data might be incomplete."));
                  success = false; // Mark as incomplete - This line is now valid
                  break; // Stop reading blocks
             }
 
             // Print bytes from this block, up to the required storedPayloadLength
             // CORRECTED: Ensure types match for min()
             uint16_t bytesToPrintFromThisBlock = min((uint16_t)BLOCK_SIZE, (uint16_t)(storedPayloadLength - bytesPrinted));
             for (uint16_t i = 0; i < bytesToPrintFromThisBlock; i++) { // Also use uint16_t for loop counter
                  if (isprint(tempBlockBuffer[i])) {
                     Serial.print((char)tempBlockBuffer[i]);
                  } else {
                     Serial.print('.'); // Replace non-printable chars with a dot
                  }
                  bytesPrinted++;
             }
              delay(5); // Small delay between block reads
         }
         Serial.println(); // Newline after printing all data
         Serial.println(F("--- End of Payload Data ---"));
         // CORRECTED: Comparison is now between two uint16_t values
         if (bytesPrinted != storedPayloadLength) {
              Serial.print(F("Warning: Expected ")); Serial.print(storedPayloadLength);
              Serial.print(F(" bytes, but only read/printed ")); Serial.print(bytesPrinted); Serial.println(F(" bytes successfully."));
         } else if (success) { // Check if loop completed without errors
              Serial.println(F("Payload read completely and successfully."));
         } else { // If bytes match but success is false, means an error occurred after printing all data? Unlikely with break statements, but good to cover.
              Serial.println(F("Payload read completely, but an error occurred during the process (e.g., final auth/read failure)."));
         }
     }
 
 
     // --- Finished with card ---
     mfrc522.PICC_HaltA();       // Halt the card
     mfrc522.PCD_StopCrypto1();  // Stop encryption on the reader
 
     Serial.println(F("Card Released. Waiting for next card..."));
     Serial.println(F("*********************************************************************"));
     Serial.println();
     delay(2000); // Wait a bit before scanning again
 }
 
 
 // =========================================================================
 // NFC Helper Functions (Adapted from Password Manager Script)
 // =========================================================================
 
 /**
  * @brief Authenticates the sector containing the specified block address using Key A.
  * Assumes 'key' and 'mfrc522' objects are globally accessible.
  *
  * @param blockAddr The block address within the sector to authenticate.
  * @return true on success, false on failure.
  */
 bool authenticateBlock(byte blockAddr) {
     byte sector = blockAddr / 4;
     byte trailerBlock = sector * 4 + 3; // Calculate sector trailer block
     MFRC522::StatusCode status;
 
     // Uncomment for debugging authentication attempts
     // Serial.print(F("Authenticating sector ")); Serial.print(sector);
     // Serial.print(F(" (trailer block ")); Serial.print(trailerBlock); Serial.println(F(")..."));
 
     status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
 
     if (status != MFRC522::STATUS_OK) {
         Serial.print(F("PCD_Authenticate() failed: "));
         Serial.println(mfrc522.GetStatusCodeName(status));
         return false;
     }
     // Serial.println(F("Authentication successful."));
     return true;
 }
 
 /**
  * @brief Reads a single 16-byte data block from the PICC.
  * Requires prior authentication of the sector.
  * Assumes 'mfrc522' object is globally accessible.
  *
  * @param blockAddr The block address to read.
  * @param buffer Pointer to the byte array where data will be stored.
  * @param bufferSize Pointer to a byte specifying buffer size. Should be at least 18.
  * On return, contains the actual number of bytes read (16).
  * @return true on success, false on failure.
  */
 bool readBlockFromNfc(byte blockAddr, byte buffer[], byte bufferSize) {
      MFRC522::StatusCode status;
 
     // Ensure buffer is large enough for MIFARE_Read (which needs 18 bytes)
     if (bufferSize < 18) {
         Serial.println(F("Error: readBlockFromNfc buffer size must be at least 18 bytes."));
         return false;
     }
 
     // Read the block
     status = mfrc522.MIFARE_Read(blockAddr, buffer, &bufferSize);
     if (status != MFRC522::STATUS_OK) {
         Serial.print(F("MIFARE_Read() failed for block ")); Serial.print(blockAddr); Serial.print(F(": "));
         Serial.println(mfrc522.GetStatusCodeName(status));
         return false;
     }
     // Uncomment for debugging read attempts
     // Serial.print(F("Successfully read block ")); Serial.println(blockAddr);
     return true;
 }