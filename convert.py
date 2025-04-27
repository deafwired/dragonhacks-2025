import serial
import pynput

MACOS = "cu.usbmodem2101"
baudrate = 115200

ser = serial.serial(MACOS, baudrate)
keyboard = Controller()

while True:
    data = ser.redaline().decode('utf-8').strip()
    if "[TYPE]" in data:
        keyboard.type(data[6:])

