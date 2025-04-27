#include <Arduino.h>
#include <LiquidCrystal_I2C.h>
#include <SPI.h>
#include <MFRC522.h>
#include <stdint.h> // Required for uint16_t

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
const int MAX_PAYLOAD_SIZE = TOTAL_USER_AREA_SIZE - HEADER_SIZE; // Max actual data size = 749 bytes

// --- Data Type Codes ---
const byte DATA_TYPE_NONE = 0x00;
const byte DATA_TYPE_PASSWORD = 0x01;

// --- NFC Key ---
MFRC522::MIFARE_Key key; // Default Key A (set in setup)

// --- Global Buffers ---
byte zeroBuffer[BLOCK_SIZE] = {0}; // Initialize all elements to 0

// --- Joystick Control Variables ---
const int threshold = 200; // Sensitivity adjustment
const unsigned long debounceDelay = 200; // Debounce time in milliseconds (using value from user example)
String lastReportedMove = "None"; // Tracks the last action reported to the main loop
unsigned long lastActionDebounceTime = 0; // Debounce timer for reporting actions

// Button specific debounce variables (closer to user example)
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
byte tempPayloadBuffer[MAX_PAYLOAD_SIZE];
uint16_t tempPayloadLength = 0;
byte tempDataType = DATA_TYPE_NONE;
String currentStatusMsg = ""; // For top row display

// --- Function Prototypes ---
// Setup & Loop
void setup();
void loop();

// Joystick
String readJoystick(); // Updated prototype if needed (no change here)

// LCD Display
void displayMainMenu();
void displayStatus(String msgTop, String msgBottom);
void displayPasswordScreen();
void setLCDMessage(String message, int row, bool centered = false);

// NFC Operations
bool initializeCardInteraction();
void finalizeCardInteraction();
bool authenticateBlock(byte blockAddr);
bool readBlockFromNfc(byte blockAddr, byte buffer[], byte bufferSize);
bool writeBlockToNfc(byte blockAddr, byte buffer[], byte bufferSize);
int readUserDataFromNfc(byte* dataType, uint16_t* dataLength, byte dataBuffer[], int bufferCapacity);
bool writeUserDataToNfc(byte dataType, byte payloadBuffer[], uint16_t payloadLength);
String generatePassword(int length);

// Helpers
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

    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF;
    }
    Serial.println("Default Key A set.");

    Serial.println("Setup Complete. Entering Main Menu...");
    currentStatusMsg = "Main Menu";
    displayMainMenu();
    // Initialize timers
    lastActionDebounceTime = millis();
    lastButtonDebounceTime = millis();
}

// =========================================================================
// Main Loop
// =========================================================================
void loop() {
    String joystickAction = readJoystick(); // Read joystick input

    // --- State Machine ---
    // (State machine logic remains the same as the previous version)
    switch (currentMenuState) {
        case STATE_MAIN_MENU:
            currentStatusMsg = "Main Menu";
            if (joystickAction == "Down" || joystickAction == "Right") {
                selectedOption = (selectedOption + 1) % 2;
                displayMainMenu();
            } else if (joystickAction == "Up" || joystickAction == "Left") {
                selectedOption = (selectedOption == 0) ? 1 : 0;
                displayMainMenu();
            } else if (joystickAction == "Click") {
                if (selectedOption == 0) { // Retrieve
                    currentMenuState = STATE_WAITING_READ;
                    currentStatusMsg = "Retrieve Pwd";
                    displayStatus(currentStatusMsg, "Scan Card...");
                } else { // Create
                    currentMenuState = STATE_WAITING_WRITE;
                    currentStatusMsg = "Create Pwd";
                    displayStatus(currentStatusMsg, "Scan Card...");
                }
            }
            break;

        case STATE_WAITING_READ:
        case STATE_WAITING_WRITE:
            if (initializeCardInteraction()) {
                if (currentMenuState == STATE_WAITING_READ) {
                    currentMenuState = STATE_READING_CARD;
                    displayStatus(currentStatusMsg, "Reading...");
                    delay(500);
                } else {
                    currentMenuState = STATE_GENERATING_PWD;
                    displayStatus(currentStatusMsg, "Generating...");
                     delay(500);
                }
            } else {
                 if (joystickAction == "Click") {
                     currentMenuState = STATE_MAIN_MENU;
                     displayMainMenu();
                 }
            }
            break;

        case STATE_READING_CARD:
            {
                int bytesRead = readUserDataFromNfc(&tempDataType, &tempPayloadLength, tempPayloadBuffer, MAX_PAYLOAD_SIZE);
                if (bytesRead >= 0) {
                    if (tempDataType == DATA_TYPE_PASSWORD && tempPayloadLength > 0) {
                         currentMenuState = STATE_SHOW_PASSWORD;
                         displayPasswordScreen();
                    } else {
                        currentStatusMsg = "No Password";
                        displayStatus(currentStatusMsg, getDataTypeName(tempDataType));
                        currentMenuState = STATE_ERROR;
                    }
                } else if (bytesRead == -2) {
                    currentMenuState = STATE_INVALID_HEADER_PROMPT;
                    currentStatusMsg = "Invalid Data";
                    displayStatus(currentStatusMsg,"Overwrite? (Y/N)");
                    selectedOption = 0; // Default to Yes (index 0)
                } else { // -1 (buffer), -3 (read/auth fail)
                    currentStatusMsg = "Read Error";
                    displayStatus(currentStatusMsg, "Check Card/Key");
                    currentMenuState = STATE_ERROR;
                }
                if (currentMenuState != STATE_INVALID_HEADER_PROMPT) {
                     finalizeCardInteraction();
                }
            }
            break;

        case STATE_INVALID_HEADER_PROMPT:
             if (joystickAction == "Left" || joystickAction == "Right") {
                 selectedOption = (selectedOption == 0) ? 1 : 0; // Toggle Yes(0)/No(1)
                 displayStatus(currentStatusMsg, selectedOption == 0 ? ">Yes   No " : " Yes  >No ");
             } else if (joystickAction == "Click") {
                 finalizeCardInteraction();
                 if (selectedOption == 0) { // Yes - Overwrite
                     currentMenuState = STATE_WAITING_WRITE;
                     currentStatusMsg = "Create Default";
                     displayStatus(currentStatusMsg, "Scan Card Again");
                 } else { // No
                     currentMenuState = STATE_MAIN_MENU;
                     displayMainMenu();
                 }
             }
            break;

        case STATE_GENERATING_PWD:
            {
                String pwd = generatePassword(16);
                tempPayloadLength = pwd.length();
                if ((int)tempPayloadLength > MAX_PAYLOAD_SIZE) tempPayloadLength = MAX_PAYLOAD_SIZE;
                memcpy(tempPayloadBuffer, pwd.c_str(), tempPayloadLength);
                tempDataType = DATA_TYPE_PASSWORD;
                Serial.print("Generated Pwd: "); Serial.println(pwd);
                currentMenuState = STATE_WRITING_CARD;
                displayStatus(currentStatusMsg, "Writing...");
                delay(500);
            }
            break;

        case STATE_WRITING_CARD:
            if (writeUserDataToNfc(tempDataType, tempPayloadBuffer, tempPayloadLength)) {
                Serial.println("Write successful.");
                currentStatusMsg = "Success!";
                displayStatus(currentStatusMsg, "Password Saved.");
            } else {
                Serial.println("Write failed.");
                currentStatusMsg = "Write Failed";
                displayStatus(currentStatusMsg, "Check Card/Key");
            }
            finalizeCardInteraction();
            currentMenuState = STATE_ERROR;
            break;

        case STATE_SHOW_PASSWORD:
            if (joystickAction == "Click") {
                currentMenuState = STATE_MAIN_MENU;
                displayMainMenu();
            }
            break;

        case STATE_ERROR:
            if (joystickAction == "Click") {
                currentMenuState = STATE_MAIN_MENU;
                displayMainMenu();
            }
            break;

        default:
             Serial.println("Error: Reached invalid state! Resetting.");
            currentMenuState = STATE_MAIN_MENU;
            displayMainMenu();
            break;
    }

    delay(10); // Small delay for stability
}

// =========================================================================
// Joystick Function (REVISED CLICK LOGIC - Based on User Example)
// =========================================================================
String readJoystick() {
    int xVal = analogRead(xPin);
    int yVal = analogRead(yPin);
    buttonState = digitalRead(buttonPin); // Read the raw button state (LOW = pressed)

    String currentDetectedMove = "None"; // What we detect in this cycle
    bool clickDetectedThisCycle = false;

    // --- Button Click Detection (Based on improved debounce logic) ---
    static int lastButtonStableState = HIGH; // Debounced button state
    static int lastButtonRawReading = HIGH;  // Last raw state reading
    // Detect raw state changes and reset debounce timer
    if (buttonState != lastButtonRawReading) {
        lastButtonDebounceTime = millis();
    }
    // After debounce delay, if raw state has stabilized and changed, update stable state
    if ((millis() - lastButtonDebounceTime) > debounceDelay) {
        if (buttonState != lastButtonStableState) {
            lastButtonStableState = buttonState;
            // Detect falling edge (pressed)
            if (buttonState == LOW) {
                clickDetectedThisCycle = true;
                Serial.println("Click!"); // Log click detection
            }
        }
    }
    // Update raw reading for next iteration
    lastButtonRawReading = buttonState;


    // --- Determine Action (Prioritize Click) ---
    if (clickDetectedThisCycle) {
        currentDetectedMove = "Click";
    } else {
        // Check directions only if no click was detected
        if (yVal < (512 - threshold)) { currentDetectedMove = "Down"; }
        else if (yVal > (512 + threshold)) { currentDetectedMove = "Up"; }
        else if (xVal < (512 - threshold)) { currentDetectedMove = "Left"; }
        else if (xVal > (512 + threshold)) { currentDetectedMove = "Right"; }
        // If none of the above, currentDetectedMove remains "None"
    }


    // --- Debounce Reporting ---
    // Report the action only if it's different from the last reported one
    // AND enough time has passed since the last report.
    if (currentDetectedMove != lastReportedMove) {
        if ((millis() - lastActionDebounceTime) > debounceDelay) {
             if (currentDetectedMove != "None") { // Don't log "None" actions unless debugging needed
                 Serial.print("Reporting Action: "); Serial.println(currentDetectedMove);
             }
            lastActionDebounceTime = millis(); // Reset reporting timer
            lastReportedMove = currentDetectedMove; // Update last reported action
            return currentDetectedMove; // Return the new action
        }
        // Else: Action changed but too soon, debounce it, return "None"
        return "None";
    } else if (currentDetectedMove == "None" && lastReportedMove != "None") {
        // Action stopped (e.g., joystick centered), allow resetting lastReportedMove after delay
        if ((millis() - lastActionDebounceTime) > debounceDelay) {
             lastReportedMove = "None";
        }
        return "None";
    }

    // If action is the same as last reported, or is "None", return "None"
    return "None";
}


// =========================================================================
// LCD Display Functions (Unchanged)
// =========================================================================
void setLCDMessage(String message, int row, bool centered) {
    if (row < 0 || row >= 2) return;
    lcd.setCursor(0, row);
    for (int i = 0; i < 16; i++) {
      lcd.print(" ");
    }
    int messageLen = message.length();
    int startCol = 0;
    if (centered && messageLen < 16) {
      startCol = (16 - messageLen) / 2;
    }
    lcd.setCursor(startCol, row);
    lcd.print(message.substring(0, 16));
  }
  void displayMainMenu() {
    setLCDMessage("Main Menu", 0, false);
    setLCDMessage((selectedOption == 0 ? ">Retrieve" : " Retrieve"), 1, false);
    lcd.setCursor(9, 1);
    lcd.print((selectedOption == 1 ? ">Create" : " Create"));
  }
  void displayStatus(String msgTop, String msgBottom) {
    setLCDMessage(msgTop, 0, false);
    setLCDMessage(msgBottom, 1, true);
  }
  void displayPasswordScreen() {
    currentStatusMsg = "Password Found";
    setLCDMessage(currentStatusMsg, 0, false);
    String pwdStr = "";
    for (int i = 0; i < (int) tempPayloadLength && i < MAX_PAYLOAD_SIZE; i++) {
      if (tempPayloadBuffer[i] == '\0') break;
      if (isprint(tempPayloadBuffer[i])) {
        pwdStr += (char) tempPayloadBuffer[i];
      } else {
        pwdStr += '?';
      }
    }
    setLCDMessage(pwdStr.substring(0, 16), 1, false);
    Serial.print("[TYPE] ");
    Serial.println(pwdStr);
  }

// =========================================================================
// NFC Card Interaction Functions (Unchanged)
// =========================================================================
bool initializeCardInteraction() {
  if (!mfrc522.PICC_IsNewCardPresent()) return false;
  if (!mfrc522.PICC_ReadCardSerial()) {
    Serial.println("Failed to read card serial.");
    return false;
  }
  Serial.print(F("Card Found! UID:"));
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }
  Serial.println();
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.print(F("PICC type: "));
  Serial.println(mfrc522.PICC_GetTypeName(piccType));
  if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI && piccType != MFRC522::PICC_TYPE_MIFARE_1K && piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
    Serial.println(F("Warning: Card type not MIFARE Classic."));
  }
  return true;
}
void finalizeCardInteraction() {
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  Serial.println(F("Card Released."));
}

// =========================================================================
// NFC Low-Level Read/Write & Helpers (Unchanged)
// =========================================================================
bool isUserDataBlock(byte blockAddr) {
  if (blockAddr >= NUM_TOTAL_BLOCKS) return false;
  if (blockAddr == 0 || (blockAddr + 1) % 4 == 0) return false;
  return true;
}
bool authenticateBlock(byte blockAddr) {
  byte sector = blockAddr / 4;
  byte trailerBlock = sector * 4 + 3;
  MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, & key, & (mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Auth Error (Block "));
    Serial.print(blockAddr);
    Serial.print(F("): "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  return true;
}
bool readBlockFromNfc(byte blockAddr, byte buffer[], byte bufferSize) {
  if (bufferSize < 18) {
    Serial.println(F("Read buffer too small (<18)"));
    return false;
  }
  MFRC522::StatusCode status = mfrc522.MIFARE_Read(blockAddr, buffer, & bufferSize);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Read Error (Block "));
    Serial.print(blockAddr);
    Serial.print(F("): "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  return true;
}
bool writeBlockToNfc(byte blockAddr, byte buffer[], byte bufferSize) {
  if (bufferSize != BLOCK_SIZE) {
    Serial.print(F("Write Error: Buffer size must be "));
    Serial.println(BLOCK_SIZE);
    return false;
  }
  if (!isUserDataBlock(blockAddr)) {
    Serial.print(F("Write Error: Attempt to write non-user block "));
    Serial.println(blockAddr);
    return false;
  }
  MFRC522::StatusCode status = mfrc522.MIFARE_Write(blockAddr, buffer, BLOCK_SIZE);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Write Error (Block "));
    Serial.print(blockAddr);
    Serial.print(F("): "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  return true;
}
int readUserDataFromNfc(byte * dataType, uint16_t * dataLength, byte dataBuffer[], int bufferCapacity) {
  byte firstBlockBuffer[18];
  byte tempBlockBuffer[18];* dataType = DATA_TYPE_NONE;* dataLength = 0;
  byte firstUserBlockAddr = userDataBlocks[0];
  if (!authenticateBlock(firstUserBlockAddr)) {
    Serial.println(F("Read User Data Error: Failed to authenticate header sector."));
    return -3;
  }
  if (!readBlockFromNfc(firstUserBlockAddr, firstBlockBuffer, sizeof(firstBlockBuffer))) {
    Serial.println(F("Read User Data Error: Failed to read first user block."));
    return -3;
  }* dataType = firstBlockBuffer[0];* dataLength = (uint16_t)(firstBlockBuffer[2] << 8) | firstBlockBuffer[1];
  if ( * dataLength > MAX_PAYLOAD_SIZE) {
    Serial.print(F("Read User Data Error: Invalid header length ("));
    Serial.print( * dataLength);
    Serial.println(F(")."));
    return -2;
  }
  if ((int) * dataLength > bufferCapacity) {
    Serial.print(F("Read User Data Error: Buffer too small ("));
    Serial.print(bufferCapacity);
    Serial.print(F(") for payload ("));
    Serial.print( * dataLength);
    Serial.println(F(")."));
    return -1;
  }
  if ( * dataLength == 0) {
    Serial.println(F("Read User Data: Header indicates zero payload length."));
    return 0;
  }
  int bytesSuccessfullyRead = 0;
  int payloadBytesReadFromFirstBlock = min((int)(BLOCK_SIZE - HEADER_SIZE), (int) * dataLength);
  if (payloadBytesReadFromFirstBlock > 0) {
    memcpy(dataBuffer, firstBlockBuffer + HEADER_SIZE, payloadBytesReadFromFirstBlock);
    bytesSuccessfullyRead += payloadBytesReadFromFirstBlock;
  }
  int currentBlockIndex = 1;
  byte currentSector = 0;
  byte lastAuthenticatedSector = 0;
  while (bytesSuccessfullyRead < (int) * dataLength && currentBlockIndex < NUM_USER_DATA_BLOCKS) {
    byte currentBlockAddr = userDataBlocks[currentBlockIndex];
    currentSector = currentBlockAddr / 4;
    if (currentSector != lastAuthenticatedSector) {
      if (!authenticateBlock(currentBlockAddr)) {
        Serial.print(F("Read User Data Error: Failed to authenticate sector "));
        Serial.println(currentSector);
        return -3;
      }
      lastAuthenticatedSector = currentSector;
    }
    if (!readBlockFromNfc(currentBlockAddr, tempBlockBuffer, sizeof(tempBlockBuffer))) {
      Serial.print(F("Read User Data Error: Failed reading payload block "));
      Serial.println(currentBlockAddr);
      return -2;
    }
    int bytesToCopyFromThisBlock = min((int) BLOCK_SIZE, (int) * dataLength - bytesSuccessfullyRead);
    memcpy(dataBuffer + bytesSuccessfullyRead, tempBlockBuffer, bytesToCopyFromThisBlock);
    bytesSuccessfullyRead += bytesToCopyFromThisBlock;
    currentBlockIndex++;
    delay(5);
  }
  if (bytesSuccessfullyRead != (int) * dataLength) {
    Serial.println(F("Read User Data Error: Length mismatch after reading blocks."));
    return -2;
  }
  return bytesSuccessfullyRead;
}
bool writeUserDataToNfc(byte dataType, byte payloadBuffer[], uint16_t payloadLength) {
  if (payloadLength > MAX_PAYLOAD_SIZE) {
    Serial.println(F("Write User Data Error: Payload too large."));
    return false;
  }
  byte tempBlockBuffer[BLOCK_SIZE];
  bool success = true;
  int totalBytesToWrite = HEADER_SIZE + payloadLength;
  int blocksNeeded = (totalBytesToWrite + BLOCK_SIZE - 1) / BLOCK_SIZE;
  int payloadBytesWritten = 0;
  byte currentSector = 0;
  byte lastAuthenticatedSector = 99;
  for (int i = 0; i < blocksNeeded; i++) {
    byte currentBlockAddr = userDataBlocks[i];
    currentSector = currentBlockAddr / 4;
    if (currentSector != lastAuthenticatedSector) {
      if (!authenticateBlock(currentBlockAddr)) {
        Serial.print(F("Write User Data Error: Failed to authenticate sector "));
        Serial.println(currentSector);
        return false;
      }
      lastAuthenticatedSector = currentSector;
    }
    memset(tempBlockBuffer, 0, BLOCK_SIZE);
    int bytesToCopyInThisBlock = 0;
    if (i == 0) {
      tempBlockBuffer[0] = dataType;
      tempBlockBuffer[1] = (byte)(payloadLength & 0xFF);
      tempBlockBuffer[2] = (byte)((payloadLength >> 8) & 0xFF);
      bytesToCopyInThisBlock = min((int)(BLOCK_SIZE - HEADER_SIZE), (int) payloadLength);
      if (bytesToCopyInThisBlock > 0) {
        memcpy(tempBlockBuffer + HEADER_SIZE, payloadBuffer, bytesToCopyInThisBlock);
        payloadBytesWritten += bytesToCopyInThisBlock;
      }
    } else {
      int remainingPayload = (int) payloadLength - payloadBytesWritten;
      bytesToCopyInThisBlock = min((int) BLOCK_SIZE, remainingPayload);
      if (bytesToCopyInThisBlock > 0) {
        memcpy(tempBlockBuffer, payloadBuffer + payloadBytesWritten, bytesToCopyInThisBlock);
        payloadBytesWritten += bytesToCopyInThisBlock;
      }
    }
    if (!writeBlockToNfc(currentBlockAddr, tempBlockBuffer, BLOCK_SIZE)) {
      Serial.print(F("Write User Data Error: Failed writing block "));
      Serial.println(currentBlockAddr);
      success = false;
      break;
    }
    delay(15);
  }
  if (success) {
    for (int i = blocksNeeded; i < NUM_USER_DATA_BLOCKS; i++) {
      byte currentBlockAddr = userDataBlocks[i];
      currentSector = currentBlockAddr / 4;
      if (currentSector != lastAuthenticatedSector) {
        if (!authenticateBlock(currentBlockAddr)) {
          Serial.print(F("Write User Data Error: Failed auth sector "));
          Serial.println(currentSector);
          success = false;
          break;
        }
        lastAuthenticatedSector = currentSector;
      }
      if (!writeBlockToNfc(currentBlockAddr, zeroBuffer, BLOCK_SIZE)) {
        Serial.print(F("Write User Data Error: Failed zeroing block "));
        Serial.println(currentBlockAddr);
        success = false;
        break;
      }
      delay(15);
    }
  }
  return success;
}
String generatePassword(int length) {
  String password = "";
  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+=-";
  const int charsetSize = sizeof(charset) - 1;
  if (length <= 0) length = 16;
  for (int i = 0; i < length; ++i) {
    password += charset[random(charsetSize)];
  }
  return password;
}
String getDataTypeName(byte dataType) {
  switch (dataType) {
  case DATA_TYPE_NONE:
    return "None";
  case DATA_TYPE_PASSWORD:
    return "Password";
  default:
    return "Unknown";
  }
}