from csv import writer
import os
import pyshark

def parsePacket(output_path, input_path, app, type, arc):
    packets = pyshark.FileCapture(input_path, use_json=True)
    print("Loading PCAP input. This may take some time...")
    packets.load_packets()
    print("Input loaded.")
    count = 0

    with open(output_path, "a", newline='') as my_csv:
        csv_writer = writer(my_csv)

        for packet in packets:
            count += 1
            sip = None
            dip = None
            prot = None
            d_proto = None
            dsfield = None
            ip_flags = None

            if hasattr(packet, 'ip'):
                sip = packet.ip.src
                dip = packet.ip.dst
                dsfield = packet.ip.dsfield
                ip_flags = packet.ip.flags

            if hasattr(packet, 'ipv6'):
                sip = packet.ipv6.src
                dip = packet.ipv6.dst

            if hasattr(packet, 'tcp'):
                prot = 'tcp'
            elif hasattr(packet, 'udp'):
                prot = 'udp'
            else:
                print("discarding non-TCP/UDP packet, detected: " + str(packet.highest_layer))
                continue

            sport = packet[packet.transport_layer].srcport
            dport = packet[packet.transport_layer].dstport

            length = packet.length
            if hasattr(packet, 'highest_layer'):
                d_proto = packet.highest_layer
            #if sip is None or dip is None or sport is None or dport is None or prot is None:
            #    pass
            properties = [sip, dip, sport, dport, prot, dsfield, ip_flags, length, str(app), str(type), str(arc), d_proto]
            csv_writer.writerow(properties)

    return count
