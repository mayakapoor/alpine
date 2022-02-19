import sys
import os
import asyncio
import argparse
import pyshark


# extracts the data layers from a given pcap and puts their string payloads into files
def extractDataLayer(sourcePcap):
    pkt = pyshark.FileCapture(sourcePcap)
    print("Loading PCAP input. This may take some time...")
    pkt.load_packets()
    print("Input loaded.")
    if not os.path.exists(os.getcwd() + "/output"):
        os.makedirs(os.getcwd() + "/output")

    sip_path = os.getcwd() + "/output/sip.txt"
    http_path = os.getcwd() + "/output/http.txt"
    ftp_path = os.getcwd() + "/output/ftp.txt"
    smtp_path = os.getcwd() + "/output/smtp.txt"

    total = len(pkt)

    for i in train_range:
        if (hasattr(pkt[i], 'sip')):
            extractSIP(pkt[i], sip_path)
        elif (hasattr(pkt[i], 'http')):
            extractHTTP(pkt[i], http_path)
        elif (hasattr(pkt[i], 'ftp')):
            extractFTP(pkt[i], ftp_path)
        elif (hasattr(pkt[i], 'smtp')):
            extractSMTP(pkt[i], path)
        elif (hasattr(pkt[i], 'pop')):
            extractPOP(pkt[i], path)
        elif (hasattr(pkt[i], 'irc')):
            extractIRC(pkt[i], path)
        elif (hasattr(pkt[i], 'rtsp')):
            extractRTSP(pkt[i], path)
        elif (hasattr(pkt[i], 'xmpp')):
            extractXMPP(pkt[i], path)

    #pysharkFile = open(path, "r", encoding="latin-1")
    datadict = {}
    sipList = fileToList(sip_path)
    datadict["SIP"] = sipList

    httpList = fileToList(http_path)
    datadict["HTTP"] = httpList

    ftpList = fileToList(ftp_path)
    datadict["FTP"] = ftpList

    smtpList = fileToList(smtp_path)
    datadict["SMTP"] = smtpList

    return datadict

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

def writeToFile(path, line):
    f = open(path, 'a+')
    f.write(line + '\n')

def extractSIP(pkt, path):
    if hasattr(pkt.sip, 'Request-Line'):
        writeToFile(path, pkt.sip.get_field_value('Request-Line'))
    elif hasattr(pkt.sip, 'Status-Line'):
        writeToFile(path, pkt.sip.get_field_value('Status-Line'))

def extractHTTP(pkt, path):
    if (hasattr(pkt.http, 'request') or hasattr(pkt.http, 'response')) and "" in pkt.http._all_fields:
        writeToFile(path, pkt.http._all_fields[""])

def extractFTP(pkt, path):
    if (pkt.ftp.request == '1' or pkt.ftp.response == '1') and "" in pkt.ftp._all_fields:
        writeToFile(path, pkt.ftp._all_fields[""])

def extractSMTP(pkt, path):
    if hasattr(pkt.smtp, 'req'):
        writeToFile(path, str(pkt.smtp.command_line))
    elif hasattr(pkt.smtp, 'rsp'):
        writeToFile(path, str(pkt.smtp.response))

def extractPOP(pkt, path):
    if hasattr(pkt.pop, 'request'):
        writeToFile(path, pkt.pop.get_field_value('request'))
    if hasattr(pkt.pop, 'response'):
        writeToFile(path, pkt.pop.get_field_value('response'))

def extractIRC(pkt, path):
    if hasattr(pkt.irc, 'request'):
        writeToFile(path, pkt.irc.get_field_value('request'))
    if hasattr(pkt.irc, 'response'):
        writeToFile(path, pkt.irc.get_field_value('response'))

def extractRTSP(pkt, path):
    if hasattr(pkt.rtsp, 'request'):
        writeToFile(path, pkt.rtsp.get_field_value('request'))
    if hasattr(pkt.rtsp, 'response'):
        writeToFile(path, pkt.rtsp.get_field_value('response'))

def extractXMPP(pkt, path):
    if "xmpp.iq" in pkt.xmpp._all_fields:
        writeToFile(path, pkt.xmpp.iq)
    if "xmpp.message" in pkt.xmpp._all_fields:
        writeToFile(path, pkt.xmpp.message)

def extractPayload(pkt, path):
    writeToFile(path, str(pkt))
