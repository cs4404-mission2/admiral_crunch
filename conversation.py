from scapy.all import * #just to supress IDE warnings
import scapy.layers.rtp
import logging
import audioop
import io
import threading 

class conversation:
    packets = []
    def __init__(self, pkt: Packet):
        self.src = pkt["IP"].src
        self.dst = pkt["IP"].dst
        self.enforce = False
        self.packets = []
        self.buffer = io.BytesIO()
        self.bufferLock = threading.Lock()

        match pkt.lastlayer().name:
            case "RTP":
                logging.warn("new conversation without SIP Hello!")
            case "Raw":
                # Assume raw data is SIP
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
            case "Raw":
                if self.parse_sip(content) == "BYE":
                    return False
            case "RTP":
                self.parse_rtp(content)
            case _:
                logging.error("attempting to add invalid packet")
        return True

    def parse_sip(self, content):
        # we pretty much only have to look for SIP goodbye
        # Yoinked from pyvoip's SIP parse function
        try:
            headers = content.split(b"\r\n\r\n")[0]
            headers_raw = headers.split(b"\r\n")
            heading = headers_raw.pop(0)
            return str(heading.split(b" ")[0], "utf8")
        except IndexError:
            logging.error("Cannot parse SIP Packet!")
            return ""
        
                
    def parse_rtp(self, content: scapy.layers.rtp.RTP):
        # Convert RTP payload to linear sound
        # re-implimentation of pyvoip's RTP library
        # Convert to linear audio
        data = audioop.ulaw2lin(content.payload, 1)
        data = audioop.bias(data, 1, 128)
        # write to audio buffer
        self.bufferLock.acquire()
        curloc = self.buffer.tell()
        self.buffer.write(data)
        #reset the buffer to where the playhead last was
        self.buffer.seek(curloc, 0)
        self.bufferLock.release()