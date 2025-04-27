// NFC Password Manager with Joystick and AES Encryption
#include <Arduino.h>
#include <LiquidCrystal_I2C.h>
#include <SPI.h>
#include <MFRC522.h>
#include <stdint.h> // Required for uint16_t
#include <AESLib.h> // <<< Include AES library

// --- Pin Definitions ---
// Joystick
const int xPin = A0; // Joystick X-axis -> Connect to Arduino A0
const int yPin = A1; // Joystick Y-axis -> Connect to Arduino A1
const int buttonPin = 2; // Joystick button (digital) -> Connect to Arduino D2

// NFC Reader (Adjust pins if necessary for your board)
#define RST_PIN 5 // Configurable, adjust to your setup -> Connect to Arduino D5
#define SS_PIN 53 // Configurable, adjust to your setup -> Connect to Arduino D53 (Mega) or D10 (Uno)

// --- Component Initialization ---
MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance
LiquidCrystal_I2C lcd(0x27, 16, 2); // Set the LCD address (0x27 is common), 16 cols, 2 rows

// --- MIFARE Classic 1K Configuration ---
const byte NUM_TOTAL_BLOCKS = 64;
const byte BLOCK_SIZE = 16;
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
// MAX_PAYLOAD_SIZE now refers to the max *encrypted* (and padded) data size that can be stored
const int MAX_PAYLOAD_SIZE = TOTAL_USER_AREA_SIZE - HEADER_SIZE; // Max stored data size = 749 bytes

// --- Data Type Codes ---
const byte DATA_TYPE_NONE = 0x00;
const byte DATA_TYPE_PASSWORD = 0x01; // Plaintext password (legacy/optional)
const byte DATA_TYPE_PASSWORD_ENC = 0x02; // <<< Encrypted password type

// --- NFC Key ---
MFRC522::MIFARE_Key key; // Default Key A (set in setup)

// --- Encryption Key (AES128 = 16 bytes) ---
// !!! WARNING: Hardcoded key - Insecure for real applications !!!
// Replace this with a securely generated and stored key if possible.
byte aes_key[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, // "01234567"
                  0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46}; // "89ABCDEF"


// --- Global Buffers ---
byte zeroBuffer[BLOCK_SIZE] = {0}; // Initialize all elements to 0

// --- Joystick Control Variables ---
const int threshold = 200; // Sensitivity adjustment
const unsigned long debounceDelay = 200; // Debounce time in milliseconds
String lastReportedMove = "None"; // Tracks the last action reported to the main loop
unsigned long lastActionDebounceTime = 0; // Debounce timer for reporting actions
int buttonState = HIGH; // Current raw button reading
int lastButtonReading = HIGH; // Last raw reading for change detection
unsigned long lastButtonDebounceTime = 0; // Timer for button debounce

// --- Menu State Machine ---
enum MenuState {
    STATE_MAIN_MENU,
    STATE_WAITING_READ,
    STATE_READING_CARD,
    STATE_WAITING_WRITE,
    STATE_GENERATING_PWD,
    STATE_WRITING_CARD,
    STATE_SHOW_PASSWORD,
    STATE_INVALID_HEADER_PROMPT,
    STATE_ERROR
};
MenuState currentMenuState = STATE_MAIN_MENU;
int selectedOption = 0; // 0: Retrieve, 1: Create in main menu

// --- Temporary Data Storage ---
byte tempPayloadBuffer[MAX_PAYLOAD_SIZE]; // Can hold plaintext or ciphertext
uint16_t tempPayloadLength = 0; // Stores actual length of data in tempPayloadBuffer (plain or cipher)
byte tempDataType = DATA_TYPE_NONE;
String currentStatusMsg = ""; // For top row display

// --- Function Prototypes ---
void setup();
void loop();
String readJoystick();
void displayMainMenu();
void displayStatus(String msgTop, String msgBottom);
void displayPasswordScreen();
void setLCDMessage(String message, int row, bool centered = false);
bool initializeCardInteraction();
void finalizeCardInteraction();
bool authenticateBlock(byte blockAddr);
bool readBlockFromNfc(byte blockAddr, byte buffer[], byte bufferSize);
bool writeBlockToNfc(byte blockAddr, byte buffer[], byte bufferSize);
int readUserDataFromNfc(byte* dataType, uint16_t* dataLength, byte dataBuffer[], int bufferCapacity);
bool writeUserDataToNfc(byte dataType, byte plainPayloadBuffer[], uint16_t plainPayloadLength); // Takes PLAINTEXT
String generatePassword(int length);
bool isUserDataBlock(byte blockAddr);
String getDataTypeName(byte dataType);

// =========================================================================
// Setup
// =========================================================================
void setup() {
    Serial.begin(115200);
    while (!Serial);
    randomSeed(analogRead(A3));
    lcd.init();
    lcd.backlight();
    setLCDMessage("Password Manager", 0, true);
    setLCDMessage("Starting...", 1, true);
    Serial.println("LCD Initialized.");
    pinMode(xPin, INPUT);
    pinMode(yPin, INPUT);
    pinMode(buttonPin, INPUT_PULLUP);
    Serial.println("Joystick Initialized.");
    SPI.begin();
    mfrc522.PCD_Init();
    delay(4);
    Serial.println("MFRC522 Initialized.");
    for (byte i = 0; i < 6; i++) { key.keyByte[i] = 0xFF; }
    Serial.println("Default Key A set.");
    Serial.println("Setup Complete. Entering Main Menu...");
    currentStatusMsg = "Main Menu";
    displayMainMenu();
    lastActionDebounceTime = millis();
    lastButtonDebounceTime = millis();
}

// =========================================================================
// Main Loop (State Machine Logic Updated for Enc Type)
// =========================================================================
void loop() {
    String joystickAction = readJoystick();

    switch (currentMenuState) {
        case STATE_MAIN_MENU:
            currentStatusMsg = "Main Menu";
            if (joystickAction == "Down" || joystickAction == "Right") { selectedOption = (selectedOption + 1) % 2; displayMainMenu(); }
            else if (joystickAction == "Up" || joystickAction == "Left") { selectedOption = (selectedOption == 0) ? 1 : 0; displayMainMenu(); }
            else if (joystickAction == "Click") {
                if (selectedOption == 0) { currentMenuState = STATE_WAITING_READ; currentStatusMsg = "Retrieve Pwd"; displayStatus(currentStatusMsg, "Scan Card..."); }
                else { currentMenuState = STATE_WAITING_WRITE; currentStatusMsg = "Create Pwd"; displayStatus(currentStatusMsg, "Scan Card..."); }
            }
            break;
        case STATE_WAITING_READ:
        case STATE_WAITING_WRITE:
            if (initializeCardInteraction()) {
                if (currentMenuState == STATE_WAITING_READ) { currentMenuState = STATE_READING_CARD; displayStatus(currentStatusMsg, "Reading..."); delay(500); }
                else { currentMenuState = STATE_GENERATING_PWD; displayStatus(currentStatusMsg, "Generating..."); delay(500); }
            } else { if (joystickAction == "Click") { currentMenuState = STATE_MAIN_MENU; displayMainMenu(); } }
            break;
        case STATE_READING_CARD: {
            // readUserDataFromNfc now handles decryption internally and returns plaintext length
            int bytesRead = readUserDataFromNfc(&tempDataType, &tempPayloadLength, tempPayloadBuffer, MAX_PAYLOAD_SIZE);
            if (bytesRead >= 0) {
                // Check for known password types (encrypted or plaintext)
                if ((tempDataType == DATA_TYPE_PASSWORD || tempDataType == DATA_TYPE_PASSWORD_ENC) && tempPayloadLength > 0) {
                    currentMenuState = STATE_SHOW_PASSWORD; displayPasswordScreen(); // Show plaintext
                } else {
                    // Card is readable but doesn't contain a known password type or is empty
                    currentStatusMsg = "No Password"; displayStatus(currentStatusMsg, getDataTypeName(tempDataType)); currentMenuState = STATE_ERROR;
                }
            } else if (bytesRead == -2) { // Invalid header or data error during read/decrypt
                currentMenuState = STATE_INVALID_HEADER_PROMPT; currentStatusMsg = "Invalid Data"; displayStatus(currentStatusMsg,"Overwrite? (Y/N)"); selectedOption = 0;
            } else { // -1 (buffer too small), -3 (read/auth fail)
                currentStatusMsg = "Read Error"; displayStatus(currentStatusMsg, "Check Card/Key"); currentMenuState = STATE_ERROR;
            }
            if (currentMenuState != STATE_INVALID_HEADER_PROMPT) { finalizeCardInteraction(); }
            } break;
        case STATE_INVALID_HEADER_PROMPT:
             if (joystickAction == "Left" || joystickAction == "Right") { selectedOption = (selectedOption == 0) ? 1 : 0; displayStatus(currentStatusMsg, selectedOption == 0 ? ">Yes   No " : " Yes  >No "); }
             else if (joystickAction == "Click") {
                 finalizeCardInteraction();
                 if (selectedOption == 0) { currentMenuState = STATE_WAITING_WRITE; currentStatusMsg = "Create Default"; displayStatus(currentStatusMsg, "Scan Card Again"); }
                 else { currentMenuState = STATE_MAIN_MENU; displayMainMenu(); }
             } break;
        case STATE_GENERATING_PWD: {
            String pwd = generatePassword(16);
            tempPayloadLength = pwd.length(); // Store plaintext length
            if ((int)tempPayloadLength > MAX_PAYLOAD_SIZE) tempPayloadLength = MAX_PAYLOAD_SIZE; // Should not happen
            // Copy plaintext password to buffer (including null terminator for encryption padding)
            memcpy(tempPayloadBuffer, pwd.c_str(), tempPayloadLength + 1);
            tempDataType = DATA_TYPE_PASSWORD_ENC; // <<< Default to encrypted type
            Serial.print("Generated Pwd: "); Serial.println(pwd);
            currentMenuState = STATE_WRITING_CARD;
            displayStatus(currentStatusMsg, "Encrypt/Write..."); // Update status message
            delay(500);
            } break;
        case STATE_WRITING_CARD:
            // Pass the PLAINTEXT password and length; encryption happens inside writeUserDataToNfc
            if (writeUserDataToNfc(tempDataType, tempPayloadBuffer, tempPayloadLength)) {
                Serial.println("Write successful."); currentStatusMsg = "Success!"; displayStatus(currentStatusMsg, "Password Saved.");
            } else {
                Serial.println("Write failed."); currentStatusMsg = "Write Failed"; displayStatus(currentStatusMsg, "Check Card/Key");
            }
            finalizeCardInteraction();
            currentMenuState = STATE_ERROR;
            break;
        case STATE_SHOW_PASSWORD:
            // Display is handled by displayPasswordScreen() which shows the (decrypted) plaintext
            if (joystickAction == "Click") { currentMenuState = STATE_MAIN_MENU; displayMainMenu(); } break;
        case STATE_ERROR:
            if (joystickAction == "Click") { currentMenuState = STATE_MAIN_MENU; displayMainMenu(); } break;
        default:
             Serial.println("Error: Reached invalid state! Resetting."); currentMenuState = STATE_MAIN_MENU; displayMainMenu(); break;
    }
    delay(10);
}

// =========================================================================
// Joystick Function (Unchanged from previous working version)
// =========================================================================
String readJoystick() {
    int xVal = analogRead(xPin); int yVal = analogRead(yPin); buttonState = digitalRead(buttonPin); String currentDetectedMove = "None"; bool clickDetectedThisCycle = false;
    static int lastButtonStableState = HIGH; static int lastButtonRawReading = HIGH;
    if (buttonState != lastButtonRawReading) { lastButtonDebounceTime = millis(); }
    if ((millis() - lastButtonDebounceTime) > debounceDelay) { if (buttonState != lastButtonStableState) { lastButtonStableState = buttonState; if (buttonState == LOW) { clickDetectedThisCycle = true; Serial.println("Click!"); } } }
    lastButtonRawReading = buttonState;
    if (clickDetectedThisCycle) { currentDetectedMove = "Click"; }
    else { if (yVal < (512 - threshold)) { currentDetectedMove = "Down"; } else if (yVal > (512 + threshold)) { currentDetectedMove = "Up"; } else if (xVal < (512 - threshold)) { currentDetectedMove = "Left"; } else if (xVal > (512 + threshold)) { currentDetectedMove = "Right"; } }
    if (currentDetectedMove != lastReportedMove) { if ((millis() - lastActionDebounceTime) > debounceDelay) { if (currentDetectedMove != "None") { Serial.print("Reporting Action: "); Serial.println(currentDetectedMove); } lastActionDebounceTime = millis(); lastReportedMove = currentDetectedMove; return currentDetectedMove; } return "None"; }
    else if (currentDetectedMove == "None" && lastReportedMove != "None") { if ((millis() - lastActionDebounceTime) > debounceDelay) { lastReportedMove = "None"; } return "None"; }
    return "None";
}


// =========================================================================
// LCD Display Functions (getDataTypeName updated)
// =========================================================================
void setLCDMessage(String message, int row, bool centered) { if (row < 0 || row >= 2) return; lcd.setCursor(0, row); for (int i = 0; i < 16; i++) { lcd.print(" "); } int messageLen = message.length(); int startCol = 0; if (centered && messageLen < 16) { startCol = (16 - messageLen) / 2; } lcd.setCursor(startCol, row); lcd.print(message.substring(0, 16)); }
void displayMainMenu() { setLCDMessage("Main Menu", 0, false); setLCDMessage( (selectedOption == 0 ? ">Retrieve" : " Retrieve"), 1, false); lcd.setCursor(9, 1); lcd.print( (selectedOption == 1 ? ">Create" : " Create") ); }
void displayStatus(String msgTop, String msgBottom) { setLCDMessage(msgTop, 0, false); setLCDMessage(msgBottom, 1, true); }
void displayPasswordScreen() {
    // Display the correct type name (Plain or Enc) based on what was read
    currentStatusMsg = getDataTypeName(tempDataType);
    setLCDMessage(currentStatusMsg, 0, false);
    // Display the actual password (which is now plaintext after decryption if needed)
    String pwdStr = "";
    for (int i = 0; i < (int)tempPayloadLength && i < MAX_PAYLOAD_SIZE; i++) { // Use tempPayloadLength (plaintext length)
        if (tempPayloadBuffer[i] == '\0') break;
         if (isprint(tempPayloadBuffer[i])) { pwdStr += (char)tempPayloadBuffer[i]; }
         else { pwdStr += '?'; }
    }
    setLCDMessage(pwdStr.substring(0, 16), 1, false);
    Serial.print("[TYPE] "); Serial.print(currentStatusMsg);
    Serial.print(" [PWD] "); Serial.println(pwdStr); // Log the displayed password
}

// =========================================================================
// NFC Card Interaction Functions (Unchanged)
// =========================================================================
bool initializeCardInteraction() { if (!mfrc522.PICC_IsNewCardPresent()) return false; if (!mfrc522.PICC_ReadCardSerial()) { Serial.println("Failed to read card serial."); return false; } Serial.print(F("Card Found! UID:")); for (byte i = 0; i < mfrc522.uid.size; i++) { Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " "); Serial.print(mfrc522.uid.uidByte[i], HEX); } Serial.println(); MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak); Serial.print(F("PICC type: ")); Serial.println(mfrc522.PICC_GetTypeName(piccType)); if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI && piccType != MFRC522::PICC_TYPE_MIFARE_1K && piccType != MFRC522::PICC_TYPE_MIFARE_4K) { Serial.println(F("Warning: Card type not MIFARE Classic.")); } return true; }
void finalizeCardInteraction() { mfrc522.PICC_HaltA(); mfrc522.PCD_StopCrypto1(); Serial.println(F("Card Released.")); }

// =========================================================================
// NFC Low-Level Read/Write & Helpers (Unchanged)
// =========================================================================
bool isUserDataBlock(byte blockAddr) { if (blockAddr >= NUM_TOTAL_BLOCKS) return false; if (blockAddr == 0 || (blockAddr + 1) % 4 == 0) return false; return true; }
bool authenticateBlock(byte blockAddr) { byte sector = blockAddr / 4; byte trailerBlock = sector * 4 + 3; MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid)); if (status != MFRC522::STATUS_OK) { Serial.print(F("Auth Error (Block ")); Serial.print(blockAddr); Serial.print(F("): ")); Serial.println(mfrc522.GetStatusCodeName(status)); return false; } return true; }
bool readBlockFromNfc(byte blockAddr, byte buffer[], byte bufferSize) { if (bufferSize < 18) { Serial.println(F("Read buffer too small (<18)")); return false; } MFRC522::StatusCode status = mfrc522.MIFARE_Read(blockAddr, buffer, &bufferSize); if (status != MFRC522::STATUS_OK) { Serial.print(F("Read Error (Block ")); Serial.print(blockAddr); Serial.print(F("): ")); Serial.println(mfrc522.GetStatusCodeName(status)); return false; } return true; }
bool writeBlockToNfc(byte blockAddr, byte buffer[], byte bufferSize) { if (bufferSize != BLOCK_SIZE) { Serial.print(F("Write Error: Buffer size must be ")); Serial.println(BLOCK_SIZE); return false; } if (!isUserDataBlock(blockAddr)) { Serial.print(F("Write Error: Attempt to write non-user block ")); Serial.println(blockAddr); return false; } MFRC522::StatusCode status = mfrc522.MIFARE_Write(blockAddr, buffer, BLOCK_SIZE); if (status != MFRC522::STATUS_OK) { Serial.print(F("Write Error (Block ")); Serial.print(blockAddr); Serial.print(F("): ")); Serial.println(mfrc522.GetStatusCodeName(status)); return false; } return true; }

// =========================================================================
// User Data Area Functions (MODIFIED for Encryption)
// =========================================================================

/**
 * @brief Reads header and payload from the user data area.
 * Handles decryption if the data type indicates encrypted data.
 *
 * @param dataType Pointer to store the read data type code (output).
 * @param dataLength Pointer to store the final payload length (plaintext length) (output).
 * @param dataBuffer Buffer to store the final payload data (plaintext) (output).
 * @param bufferCapacity The maximum size of dataBuffer.
 * @return The number of plaintext payload bytes successfully read, or negative error code.
 */
int readUserDataFromNfc(byte* dataType, uint16_t* dataLength, byte dataBuffer[], int bufferCapacity) {
    byte firstBlockBuffer[18];
    byte tempBlockBuffer[18];
    *dataType = DATA_TYPE_NONE;
    *dataLength = 0; // This will store the length read from header (plain or cipher) initially
    uint16_t storedLength = 0; // Use a separate variable for header length
    byte firstUserBlockAddr = userDataBlocks[0];

    // Authenticate and read the first block containing the header
    if (!authenticateBlock(firstUserBlockAddr)) {
        Serial.println(F("Read Error: Auth Header Fail"));
        return -3;
    }
    if (!readBlockFromNfc(firstUserBlockAddr, firstBlockBuffer, sizeof(firstBlockBuffer))) {
         Serial.println(F("Read Error: Read Header Fail"));
        return -3;
    }

    // Parse header
    *dataType = firstBlockBuffer[0];
    storedLength = (uint16_t)(firstBlockBuffer[2] << 8) | firstBlockBuffer[1]; // Length of stored data

    // Validate header data
    if (storedLength > MAX_PAYLOAD_SIZE) { Serial.print(F("Read Error: Invalid header length")); return -2; }
    // For encrypted data, stored length must be multiple of 16 (unless 0)
    if (*dataType == DATA_TYPE_PASSWORD_ENC && storedLength > 0 && (storedLength % 16 != 0)) { Serial.print(F("Read Error: Enc len not mult 16")); return -2; }
    // Check if buffer can hold the *stored* data (might be ciphertext)
    if ((int)storedLength > bufferCapacity) { Serial.print(F("Read Error: Buffer too small")); return -1; }

    if (storedLength == 0) {
        *dataLength = 0; // Ensure output length is 0
        return 0; // Valid header, zero length payload
    }

    // --- Read the payload (encrypted or plaintext) into dataBuffer ---
    int bytesSuccessfullyRead = 0;
    int payloadBytesReadFromFirstBlock = min((int)(BLOCK_SIZE - HEADER_SIZE), (int)storedLength);
    if (payloadBytesReadFromFirstBlock > 0) {
         memcpy(dataBuffer, firstBlockBuffer + HEADER_SIZE, payloadBytesReadFromFirstBlock);
         bytesSuccessfullyRead += payloadBytesReadFromFirstBlock;
    }

    int currentBlockIndex = 1;
    byte currentSector = 0;
    byte lastAuthenticatedSector = 0; // Sector 0 was already authenticated

    while (bytesSuccessfullyRead < (int)storedLength && currentBlockIndex < NUM_USER_DATA_BLOCKS) {
        byte currentBlockAddr = userDataBlocks[currentBlockIndex];
        currentSector = currentBlockAddr / 4;
        if (currentSector != lastAuthenticatedSector) {
             if (!authenticateBlock(currentBlockAddr)) { Serial.print(F("Read Error: Auth Fail Sec")); Serial.println(currentSector); return -3; }
             lastAuthenticatedSector = currentSector;
        }
        if (!readBlockFromNfc(currentBlockAddr, tempBlockBuffer, sizeof(tempBlockBuffer))) { Serial.print(F("Read Error: Read Fail Blk")); Serial.println(currentBlockAddr); return -2; }
        int bytesToCopyFromThisBlock = min((int)BLOCK_SIZE, (int)storedLength - bytesSuccessfullyRead);
        memcpy(dataBuffer + bytesSuccessfullyRead, tempBlockBuffer, bytesToCopyFromThisBlock);
        bytesSuccessfullyRead += bytesToCopyFromThisBlock;
        currentBlockIndex++;
        delay(5);
    }

    // Verify we read the amount specified in the header
    if (bytesSuccessfullyRead != (int)storedLength) { Serial.println(F("Read Error: Length mismatch")); return -2; }

    // --- Decrypt if necessary ---
    if (*dataType == DATA_TYPE_PASSWORD_ENC) {
        Serial.println("Decrypting data...");
        // AESLib expects length to be multiple of 16, already checked
        uint16_t numBlocks = storedLength / 16;
        for (uint16_t i = 0; i < numBlocks; i++) {
            aes128_dec_single(aes_key, dataBuffer + i * 16); // Decrypt block by block in place
        }
        // Find the actual length by looking for the first null terminator
        // The buffer should be null-terminated by the padding applied before encryption
        *dataLength = strlen((char*)dataBuffer); // Update output length to plaintext length
        // Optional: Zero out the rest of the buffer after the null terminator for security
        // memset(dataBuffer + *dataLength, 0, bufferCapacity - *dataLength);
        Serial.print("Decrypted Length: "); Serial.println(*dataLength);
    } else {
        // For plaintext, the output length is the stored length
        *dataLength = storedLength;
    }

    // Return the number of *meaningful* bytes (plaintext length)
    return *dataLength;
}


/**
 * @brief Writes header and payload, encrypting if necessary.
 * Takes PLAINTEXT payload as input.
 *
 * @param dataType The data type code (e.g., DATA_TYPE_PASSWORD_ENC).
 * @param plainPayloadBuffer Buffer containing the PLAINTEXT data to write.
 * @param plainPayloadLength The number of bytes in plainPayloadBuffer to write.
 * @return true if all writes were successful, false otherwise.
 */
bool writeUserDataToNfc(byte dataType, byte plainPayloadBuffer[], uint16_t plainPayloadLength) {
    byte dataToWrite[TOTAL_USER_AREA_SIZE]; // Temp buffer for header + (padded/encrypted) data
    uint16_t finalStoredLength = 0; // Length of data to be stored on card (plain or cipher)

    // --- Prepare data (Encrypt and Pad if needed) ---
    if (dataType == DATA_TYPE_PASSWORD_ENC) {
        Serial.println("Encrypting data...");
        // Calculate padded length (must be multiple of 16)
        // Include space for null terminator before padding calculation
        uint16_t lengthWithNull = plainPayloadLength + 1;
        uint16_t paddedLength = lengthWithNull;
        if (paddedLength % 16 != 0) {
            paddedLength = ((paddedLength / 16) + 1) * 16;
        }

        // Check if padded data exceeds storage capacity
        if (paddedLength > MAX_PAYLOAD_SIZE) {
            Serial.println("Write Error: Payload too large after padding.");
            return false;
        }

        // Create padded buffer dynamically or use a sufficiently large global/static one if memory is tight
        // Using dynamic allocation here for clarity, ensure enough heap space or use static buffer
        byte paddedData[paddedLength]; // VLA - use with caution or make static/global
        if (!paddedData) { Serial.println("Write Error: Mem alloc fail"); return false; } // Check allocation

        memcpy(paddedData, plainPayloadBuffer, plainPayloadLength);
        // Add null terminator and pad with nulls (important for decryption length recovery)
        memset(paddedData + plainPayloadLength, 0, paddedLength - plainPayloadLength);

        Serial.print("Plain Length: "); Serial.println(plainPayloadLength);
        Serial.print("Padded Length: "); Serial.println(paddedLength);

        // Encrypt the padded data IN PLACE
        uint16_t numBlocks = paddedLength / 16;
        for (uint16_t i = 0; i < numBlocks; i++) {
             aes128_enc_single(aes_key, paddedData + i * 16);
        }

        // Prepare the final buffer to write (Header + Encrypted Padded Data)
        finalStoredLength = paddedLength; // Header stores the encrypted length
        dataToWrite[0] = dataType;
        dataToWrite[1] = (byte)(finalStoredLength & 0xFF);
        dataToWrite[2] = (byte)((finalStoredLength >> 8) & 0xFF);
        memcpy(dataToWrite + HEADER_SIZE, paddedData, finalStoredLength);

    } else {
        // Handle plaintext or other types (no encryption/padding needed)
        finalStoredLength = plainPayloadLength; // Header stores plaintext length
        if (finalStoredLength > MAX_PAYLOAD_SIZE) {
             Serial.println("Write Error: Payload too large.");
             return false;
        }
        dataToWrite[0] = dataType;
        dataToWrite[1] = (byte)(finalStoredLength & 0xFF);
        dataToWrite[2] = (byte)((finalStoredLength >> 8) & 0xFF);
        memcpy(dataToWrite + HEADER_SIZE, plainPayloadBuffer, finalStoredLength);
    }

    // --- Write the prepared data (dataToWrite) to NFC ---
    bool success = true;
    int totalBytesToWrite = HEADER_SIZE + finalStoredLength; // Total bytes including header
    int blocksNeeded = (totalBytesToWrite + BLOCK_SIZE - 1) / BLOCK_SIZE; // Blocks for header+data
    byte currentSector = 0;
    byte lastAuthenticatedSector = 99; // Force first auth

    Serial.print("Total bytes to write to card (incl. header): "); Serial.println(totalBytesToWrite);
    Serial.print("Blocks needed for data: "); Serial.println(blocksNeeded);


    for (int i = 0; i < blocksNeeded; i++) {
        byte currentBlockAddr = userDataBlocks[i];
        currentSector = currentBlockAddr / 4;

        if (currentSector != lastAuthenticatedSector) {
            if (!authenticateBlock(currentBlockAddr)) { Serial.print(F("Write Error: Auth Fail Sec")); Serial.println(currentSector); success = false; break; }
            lastAuthenticatedSector = currentSector;
        }

        // Prepare the 16-byte block to write from dataToWrite buffer
        byte blockBuffer[BLOCK_SIZE];
        int offset = i * BLOCK_SIZE; // Offset within the dataToWrite buffer
        // Calculate how many bytes to copy from dataToWrite for this block
        int bytesToCopy = min((int)BLOCK_SIZE, totalBytesToWrite - offset);

        memset(blockBuffer, 0, BLOCK_SIZE); // Zero out block buffer first
        if (bytesToCopy > 0) {
            memcpy(blockBuffer, dataToWrite + offset, bytesToCopy);
        }
        // If bytesToCopy < 16, the rest is already zeroed (padding the write area)

        if (!writeBlockToNfc(currentBlockAddr, blockBuffer, BLOCK_SIZE)) {
            Serial.print(F("Write Error: Write Fail Blk")); Serial.println(currentBlockAddr);
            success = false; break; // Stop writing if an error occurs
        }
        delay(15); // Write delay
    }

    // --- Zero out remaining user data blocks (if write was successful so far) ---
    if (success) {
        Serial.print("Zeroing blocks from index "); Serial.println(blocksNeeded);
        for (int i = blocksNeeded; i < NUM_USER_DATA_BLOCKS; i++) {
             byte currentBlockAddr = userDataBlocks[i];
             currentSector = currentBlockAddr / 4;
             if (currentSector != lastAuthenticatedSector) {
                 if (!authenticateBlock(currentBlockAddr)) { Serial.print(F("Write Error: Zero Auth Fail Sec")); Serial.println(currentSector); success = false; break; }
                 lastAuthenticatedSector = currentSector;
             }
             // Use the global zeroBuffer for efficiency
             if (!writeBlockToNfc(currentBlockAddr, zeroBuffer, BLOCK_SIZE)) {
                 Serial.print(F("Write Error: Zero Fail Blk")); Serial.println(currentBlockAddr);
                 success = false; break; // Stop zeroing if an error occurs
             }
             delay(15); // Write delay
        }
    }

    return success;
}

// =========================================================================
// Helper Functions (generatePassword, getDataTypeName updated)
// =========================================================================
String generatePassword(int length) { String password = ""; const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+=-"; const int charsetSize = sizeof(charset) - 1; if (length <= 0) length = 16; for (int i = 0; i < length; ++i) { password += charset[random(charsetSize)]; } return password; }

String getDataTypeName(byte dataType) {
    switch (dataType) {
        case DATA_TYPE_NONE: return "None";
        case DATA_TYPE_PASSWORD: return "Password (Plain)"; // Clarify plain
        case DATA_TYPE_PASSWORD_ENC: return "Password (Enc)"; // New type
        default: return "Unknown";
    }
}
