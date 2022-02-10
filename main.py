from extract import *
import os
from forest import *

def load_file(file_path):
    pysharkList = []

    #check if file exists
    if not os.path.exists(file_path):
        print("ERROR: pre-processed data does not exist.")
        exit()

    pysharkFile = open(file_path, "r", encoding="latin-1")

    #get the number of non empty lines in the file
    for line in pysharkFile:
        pysharkList.append(line.rstrip())

    pysharkFile.close()
    return pysharkList

def pcapInput():
    #reading each pcap and calling the pysharkOutput function
    for i in args.pcap:
        with open(i, 'r') as f:
            path = pysharkOutput(i)
    return path

def pysharkOutput(sourcePcap):
    pkt = pyshark.FileCapture(sourcePcap)
    print("Loading PCAP input. This may take some time...")
    pkt.load_packets()
    print("Input loaded.")
    if not os.path.exists(os.getcwd() + "/output"):
        os.makedirs(os.getcwd() + "/output")
    path = os.getcwd() + "/output/extractout.txt"

    total = len(pkt)

    for i in range(total):
        if (hasattr(pkt[i], 'sip')):
            extractSIP(pkt[i], path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process pcap file and integer data.")
    parser.add_argument("-pcap", nargs="+", help="The pcap file. Multiple pcaps can be added when separated by a space.")
    args = parser.parse_args()
    pysharkList = []
    #need a static mapping of protocols to IDs, and match of training data/hash index to protocol ID
    buckets = {}

    for f in args.pcap:
        pysharkList += load_file(f)

    shingleBox = []
    i = 0

    for line in pysharkList:
        shingleBox.append(line.split())
        i = i + 1

    #print(shingleBox)
    forest = make_forest(shingleBox, 128)

    for line in pysharkList:
        arr = query_forest(line, 128, 10, forest)
        print(arr)
