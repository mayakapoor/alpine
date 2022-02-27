#-----------------------------------------------------------------------------#
# This code is written to aid with pre-processing PCAPs, specifically creating
# labeled training data for supervised techniques.
#-----------------------------------------------------------------------------#

import sys
import os
import asyncio
import argparse
import pyshark

#----------------------#
#   Helper functions
#----------------------#

# convert a file of strings to a list of strings
# \aram[in] path the path of the file
# \return the list of strings
def fileToList(path):
    lst = []
    try:
        f = open(path, "r", encoding="latin-1")
    except:
        return lst
    for line in f:
        lst.append(line.rstrip())
    f.close()
    return lst

# write a line to the file at path
def writeToFile(path, line):
    f = open(path, 'a+')
    f.write(line + '\n')


# extracts the data layers from a given pcap and puts their string payloads into a dictionary of label : strings
# \param[in] sourcePcap the pcap to extract data from
# \return the data dictionary
def extractDataLayer(sourcePcap):
    pkt = pyshark.FileCapture(sourcePcap)
    print("Loading PCAP input. This may take some time...")
    pkt.load_packets()
    print("Input loaded.")
    if not os.path.exists(os.getcwd() + "/output"):
        os.makedirs(os.getcwd() + "/output")

    # STEP 1: define your classes here
    sip_paths = []
    http_paths = []
    ftp_paths = []
    smtp_paths = []

    sip_paths.append(os.getcwd() + "/output/siprequest.txt")
    sip_paths.append(os.getcwd() + "/output/sipresponse.txt")
    http_paths.append(os.getcwd() + "/output/httprequest.txt")
    http_paths.append(os.getcwd() + "/output/httpresponse.txt")
    ftp_paths.append(os.getcwd() + "/output/ftprequest.txt")
    ftp_paths.append(os.getcwd() + "/output/ftpresponse.txt")
    smtp_paths.append(os.getcwd() + "/output/smtprequest.txt")
    smtp_paths.append(os.getcwd() + "/output/smtpresponse.txt")

    # STEP 2: parse the strings based on type.
    #         we write these to file for error checking/bookkeeping.
    for i in range(len(pkt)):
        if (hasattr(pkt[i], 'tcp')):
            print(pkt[i].tcp.payload)
        if (hasattr(pkt[i], 'udp')):
            print(pkt[i].udp.payload)
        if (hasattr(pkt[i], 'sip')):
            extractSIP(pkt[i], sip_paths)
        elif (hasattr(pkt[i], 'http')):
            extractHTTP(pkt[i], http_paths)
        elif (hasattr(pkt[i], 'ftp')):
            extractFTP(pkt[i], ftp_paths)
        elif (hasattr(pkt[i], 'smtp')):
            extractSMTP(pkt[i], smtp_paths)
        elif (hasattr(pkt[i], 'pop')):
            extractPOP(pkt[i], path)
        elif (hasattr(pkt[i], 'irc')):
            extractIRC(pkt[i], path)
        elif (hasattr(pkt[i], 'rtsp')):
            extractRTSP(pkt[i], path)
        elif (hasattr(pkt[i], 'xmpp')):
            extractXMPP(pkt[i], path)

    # STEP 3: put it all in a dictionary of label : data
    datadict = {}

    for path in sip_paths:
        sipList = fileToList(path)
        datadict["SIP"] = sipList
    for path in http_paths:
        httpList = fileToList(path)
        datadict["HTTP"] = httpList
    for path in ftp_paths:
        ftpList = fileToList(path)
        datadict["FTP"] = ftpList
    for path in smtp_paths:
        smtpList = fileToList(path)
        datadict["SMTP"] = smtpList

    return datadict

# the following functions extract payloads from protocols and sort them by types.

def extractSIP(pkt, path):
    if hasattr(pkt.sip, 'Request-Line'):
        writeToFile(path[0], pkt.sip.get_field_value('Request-Line'))
    elif hasattr(pkt.sip, 'Status-Line'):
        writeToFile(path[1], pkt.sip.get_field_value('Status-Line'))

def extractHTTP(pkt, path):
    if hasattr(pkt.http, 'request') and "" in pkt.http._all_fields:
        writeToFile(path[0], pkt.http._all_fields[""])
    if hasattr(pkt.http, 'response') and "" in pkt.http._all_fields:
        writeToFile(path[1], pkt.http._all_fields[""])

def extractFTP(pkt, path):
    if pkt.ftp.request == '1' and "" in pkt.ftp._all_fields:
        writeToFile(path[0], pkt.ftp._all_fields[""])
    if pkt.ftp.response == '1' and "" in pkt.ftp._all_fields:
        writeToFile(path[1], pkt.ftp._all_fields[""])

def extractSMTP(pkt, path):
    if hasattr(pkt.smtp, 'req'):
        writeToFile(path[0], str(pkt.smtp.command_line))
    elif hasattr(pkt.smtp, 'rsp'):
        writeToFile(path[1], str(pkt.smtp.response))

def extractPOP(pkt, path):
    if hasattr(pkt.pop, 'request'):
        writeToFile(path[0], pkt.pop.get_field_value('request'))
    if hasattr(pkt.pop, 'response'):
        writeToFile(path[1], pkt.pop.get_field_value('response'))

def extractIRC(pkt, path):
    if hasattr(pkt.irc, 'request'):
        writeToFile(path[0], pkt.irc.get_field_value('request'))
    if hasattr(pkt.irc, 'response'):
        writeToFile(path[1], pkt.irc.get_field_value('response'))

def extractRTSP(pkt, path):
    if hasattr(pkt.rtsp, 'request'):
        writeToFile(path[0], pkt.rtsp.get_field_value('request'))
    if hasattr(pkt.rtsp, 'response'):
        writeToFile(path[1], pkt.rtsp.get_field_value('response'))

def extractXMPP(pkt, path):
    if "xmpp.iq" in pkt.xmpp._all_fields:
        writeToFile(path[0], pkt.xmpp.iq)
    if "xmpp.message" in pkt.xmpp._all_fields:
        writeToFile(path[1], pkt.xmpp.message)

def extractPayload(pkt, path):
    writeToFile(path, str(pkt))
