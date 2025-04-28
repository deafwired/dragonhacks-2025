import serial
from pynput.keyboard import Key, Controller

MACOS = "/dev/cu.usbmodem1101"
baudrate = 115200

ser = serial.Serial(MACOS, baudrate)
keyboard = Controller()

while True:
    data = ser.readline().decode('utf-8').strip()

    if "[TYPE]" in data:
        keyboard.type(data[6:])
        keyboard.press(Key.enter)
        keyboard.release(Key.enter)