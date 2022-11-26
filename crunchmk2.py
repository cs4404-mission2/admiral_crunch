#!/usr/bin/python3
# Python rewrite of python rewrite of admiral crunch
from scapy.all import *
from scapy.layers import inet, rtp
import scapy.sendrecv
from conversation import *
import logging

cstore = convostore()

gb = girlboss()

def gatekeep(pkt: Packet):
    '''decides how packets should flow through the bridge'''
    global cstore, gb
    # If Packet isn't VOIP, we don't care about it
    if not pkt.haslayer("UDP"):
        return True
    if pkt.lastlayer().name != "Raw" and pkt.lastlayer().name != "RTP":
                return True
    match pkt.lastlayer().name:
        case "Raw":
            # Assume raw packets are SIP since scapy can't understand SIP
            # Future: maybe select by port number?
            parsed = parse_sip(pkt.lastlayer().payload)
            if parsed["message"] == "BYE":
                logging.info("recieved SIP BYE, dumping conversation")
                # TODO: remove conversation from convo list
            elif parsed["message"] == "INVITE":
                logging.info("Got new call")
                # TODO: Handle new call


def parse_sip(self, content):
    '''Interprit SIP header data'''
    retn = {"message":"","To_ip":"","From_ip":"",
    "To_ext":"","From_ext":""}
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


packetlog = scapy.sendrecv.bridge_and_sniff(if1='enp5s0',if2='enp5s1',xfrm12=gatekeep)
packetlog.show()