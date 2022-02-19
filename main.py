from extract import *
import os
from alpine import Alpine

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process pcap file and integer data.")
    parser.add_argument("-pcap", nargs="+", help="The pcap file. Multiple pcaps can be added when separated by a space.")
    args = parser.parse_args()
    forest = Alpine(128)

    for f in args.pcap:
        datadict = extractDataLayer(f)
        for bucket in datadict:
            shingleBox = []
            i = 0
            for line in datadict[bucket]:
                shingleBox.append(line.split())
                i = i + 1
                if (i >= len(datadict[bucket]) * 0.8):
                    break
            forest.add_bucket(shingleBox, bucket)

    forest.finalize()

    datadict = extractDataLayer(f)
    for bucket in datadict:
        for line in datadict[bucket]:
            print(forest.query(line, 10))
