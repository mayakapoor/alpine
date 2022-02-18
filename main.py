from extract import *
import os
from alpine import Alpine

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process pcap file and integer data.")
    parser.add_argument("-pcap", nargs="+", help="The pcap file. Multiple pcaps can be added when separated by a space.")
    args = parser.parse_args()
    forest = Alpine(128)

    for f in args.pcap:
        pysharkList = extractDataLayer(f)
        shingleBox = []
        i = 0
        for line in pysharkList:
            shingleBox.append(line.split())
            i = i + 1
        # TODO: split up the labels and data parsing to proper buckets
        forest.add_bucket(shingleBox, "null")

    forest.finalize()

    pysharkList = extractDataLayer(f)
    for line in pysharkList:
        print(forest.query(line, 10))
