# -*- coding:utf-8 -*-
__author__ = "sherlly"
__version__ = "1.1"


import argparse
from common.png import PNG
from common.util import ReadFile, Termcolor


if __name__ == "__main__":

    msg = f"""
	 ____   ____ ____ _____ 
	|  _ \ / ___|  _ \_   _|
	| |_) | |   | |_) || |  
	|  __/| |___|  _ < | |  
	|_|    \____|_| \_\|_|  

	PNG Check & Repair Tool 

Project address: https://github.com/sherlly/PCRT
Author: sherlly
Version: {__version__}
	"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", action="store_true", help="don't show the banner infomation")
    parser.add_argument("-y", "--yes", help="auto choose yes", action="store_true")
    parser.add_argument("-v", "--verbose", help="use the safe way to recover", action="store_true")
    parser.add_argument("-m", "--message", help="show the image information", action="store_true")
    parser.add_argument("-n", "--name", help="payload name [Default: random]")
    parser.add_argument("-p", "--payload", help="payload to hide")
    parser.add_argument(
        "-w", "--way", type=int, default=1, help="payload chunk: [1]: ancillary [2]: critical [Default:1]"
    )

    parser.add_argument("-d", "--decompress", help="decompress zlib data file name")
    parser.add_argument("-bf", "--bruteforce", action="store_true", help="Don't fix IHDR CRC to current data, rather bruteforce PNG dimension to match current IHDR CRC. (up to 4000 x 4000)")
    parser.add_argument("-i", "--input", help="Input file name (*.png) [Select from terminal]")
    parser.add_argument("-f", "--file", help="Input file name (*.png) [Select from window]", action="store_true")
    parser.add_argument("-o", "--output", default="output.png", help="Output repaired file name [Default: output.png]")
    args = parser.parse_args()

    in_file = args.input
    out_file = args.output
    payload = args.payload
    payload_name = args.name
    z_file = args.decompress

    if args.quiet is True:
        print(msg)

    if z_file is not None:
        z_data = ReadFile(z_file)
        my_png = PNG()
        my_png.DecompressPNG(z_data, width=0, height=0)
    else:
        if args.verbose is True:
            mode = 1
        else:
            mode = 0
        if args.file is True:
            try:
                import Tkinter
                import tkFileDialog

                root = Tkinter.Tk()
                in_file = tkFileDialog.askopenfilename()
                root.destroy()
                if args.yes is True:
                    my_png = PNG(in_file, out_file, choices="y", mode=mode)
                else:
                    my_png = PNG(in_file, out_file, mode=mode)
                if args.message is True:
                    my_png.PrintPicInfo()
                elif payload is not None:
                    way = args.way
                    my_png.AddPayload(payload_name, payload, way)
                else:
                    my_png.CheckPNG()
            except ImportError as e:
                print(Termcolor("Error", e))
                print("Try 'pip install Tkinter' to use it")
        elif in_file is not None:
            if args.yes is True:
                my_png = PNG(in_file, out_file, choices="y", mode=mode, ihdr_bruteforce=args.bruteforce)
            else:
                my_png = PNG(in_file, out_file, mode=mode, ihdr_bruteforce=args.bruteforce) 
            if args.message is True:
                my_png.PrintPicInfo()
            elif payload is not None:
                way = args.way
                my_png.AddPayload(payload_name, payload, way)
            else:
                my_png.CheckPNG()
        else:
            parser.print_help()
