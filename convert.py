import serial
import pynput

MACOS = "/dev/cu.usbmodem2101"
baudrate = 115200

ser = serial.Serial(MACOS, baudrate)
keyboard = pynput.keyboard.Controller()

while True:
    data = ser.redaline().decode('utf-8').strip()
    if "[TYPE]" in data:
        keyboard.type(data[6:])

