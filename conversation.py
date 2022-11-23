from scapy.all import * #just to supress IDE warnings
import logging

class conversation:
    packets = []
    def __init__(self, pkt: Packet):
        self.src = pkt["IP"].src
        self.dst = pkt["IP"].dst
        self.enforce = False
        self.packets = []
        match pkt["UDP"].payload.name:
            case "RTP":
                logging.warn("new conversation without SIP Hello!")
            case "SIP":
                #TODO: sippy stuff
                print("Not yet implimented")


    def get_enforce(self, pkt: Packet["UDP"]):
        '''Checks if conversation should be manipulated
        Returns: 0-packet does not correspond to this conversation
        1- packet corresponds and conversation is not enforcing
        2- packet corresponds and should be enforced'''
        try:
            ip1 = pkt["IP"].src
            ip2 = pkt["IP"].dst
        except IndexError:
            logging.warning("Analysis thread: got bad packet!")
            return 0
        if (self.src == ip1 and self.dst == ip2) or (self.src == ip2 and self.dst == ip1):
            if self.enforce:
                return 2
            return 1
    
    def add(self, pkt: Packet):
        '''parses packet content and add to memory'''
        content = pkt.lastlayer()
        match content.name:
            case "SIP" | "Raw":
                self.parse_sip(content)
            case "RTP":
                self.parse_rtp(content)
            case _:
                logging.error("attempting to add invalid packet")

    def parse_sip(self, content):
        # we pretty much only have to look for SIP goodbye
        print("Not yet implimented")
                
    def parse_rtp(self, content: scapy.layers.rtp.RTP):
        # Convert RTP payload to linear sound
        print("Not yet implimented")