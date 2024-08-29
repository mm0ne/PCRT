import os
import platform
import sys
import struct

if platform.system() == "Windows":
    import ctypes

    STD_OUTPUT_HANDLE = -11
    FOREGROUND_BLUE = 0x09
    FOREGROUND_GREEN = 0x0A
    FOREGROUND_RED = 0x0C
    FOREGROUND_SKYBLUE = 0x0B
    std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

    def set_cmd_text_color(color, handle=std_out_handle):
        status = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
        return status

    def resetColor():
        set_cmd_text_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

    def printRed(msg):
        set_cmd_text_color(FOREGROUND_RED)
        sys.stdout.write(msg)
        resetColor()

    def printSkyBlue(msg):
        set_cmd_text_color(FOREGROUND_SKYBLUE)
        sys.stdout.write(msg)
        resetColor()

    def printGreen(msg):
        set_cmd_text_color(FOREGROUND_GREEN)
        sys.stdout.write(msg)
        resetColor()


def WriteFile(filename):
    if os.path.isfile(filename) is True:
        os.remove(filename)
    file = open(filename, "wb+")
    return file


def ReadFile(filename):
    try:
        with open(filename, "rb") as file:
            data = file.read()
    except IOError as e:
        print(Termcolor("Error", e[1] + ": " + filename))
        return -1
    return data


def Termcolor(flag, sentence):
    # check platform
    system = platform.system()
    if system == "Linux" or system == "Darwin":
        if flag == "Notice":
            return "\033[0;34m[%s]\033[0m %s" % (flag, sentence)
        elif flag == "Detected":
            return "\033[0;32m[%s]\033[0m %s" % (flag, sentence)
        elif flag == "Error" or flag == "Warning" or flag == "Failed":
            return "\033[0;31m[%s]\033[0m %s" % (flag, sentence)
    elif system == "Windows":
        try:

            if flag == "Notice":
                printSkyBlue("[%s] " % flag)
                return sentence
            elif flag == "Detected":
                printGreen("[%s] " % flag)
                return sentence
            elif flag == "Error" or flag == "Warning" or flag == "Failed":
                printRed("[%s] " % flag)
                return sentence
        except ImportError as e:
            print("[Error]", e)
            print("Using the normal color to show...")
            return "[%s] %s" % (flag, sentence)
    else:
        return "[%s] %s" % (flag, sentence)


def byte2hexstring(b: bytes) -> str:
    return "0x" + b.hex().upper()


def int2hexstring(i: int):
    return "0x" + hex(i).upper()[2:]
