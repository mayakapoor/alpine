from preprocessing import *
from preprocess import *
import os
from csv import writer
from alpine import Alpine

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process pcap file and integer data.")
    parser.add_argument("-pcap", nargs="+", help="The pcap file. Multiple pcaps can be added when separated by a space.")
    parser.add_argument("-application", help ="The application label (ex: Facebook)")
    parser.add_argument("-traffictype", help = "The traffic type label (ex: Chat)")
    parser.add_argument("-architecture", help = "The architecture label (ex: VPN)")
    args = parser.parse_args()

    #if len(args.pcap) != len(args.appli):
    #    print("mismatched number of labels and pcaps provided.")
    #    exit()

    columns=["src_ip", "dst_ip", "src_port", "dst_port", "t_proto", "dsfield", "ip_flags", "length", "application", "traffic_type", "arc", "d_proto"]

    output_prefix = os.getcwd() + "/output"
    if not os.path.exists(output_prefix):
        os.makedirs(output_prefix)
    filecount = 0
    ext = str(filecount) + ".csv"
    filename = (output_prefix + "/" + str(args.application) + str(args.traffictype) + str(args.architecture))

    with open(filename + ext, "w", newline='') as my_csv:
        csv_writer = writer(my_csv)
        csv_writer.writerow(columns)

    #forest = Alpine(128)
    total = 0
    for f in args.pcap:
        total += parsePacket(filename + ext, f, args.application, args.traffictype, args.architecture)
        if (total % 100000 == 0):
            filecount += 1
            ext = str(filecount) + ".csv"
            with open(filename + ext, "w", newline='') as my_csv:
                csv_writer = writer(my_csv)
                csv_writer.writerow(columns)

    print("Number of packets processed: %d" % total)

        #text-based
        #datadict = extractDataLayer(f)
        #for bucket in datadict:
        #    shingleBox = []
        #    i = 0
        #    for line in datadict[bucket]:
        #        shingleBox.append(line.split())
        #        i = i + 1
        #        if (i >= len(datadict[bucket]) * 0.8):
        #            break
        #    forest.add_bucket(shingleBox, bucket)

    #forest.finalize()

    #datadict = extractDataLayer(f)
    #for bucket in datadict:
    #    for line in datadict[bucket]:
    #        print(forest.query(line, 10))
