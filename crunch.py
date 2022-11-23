#!/usr/bin/python3
# This is a rewrite of Admiral Crunch in python
import audioop
from scapy.all import *
from scapy.layers import inet, rtp
import scapy.sendrecv
import conversation
from queue import Queue
from threading import Thread
import logging


# This function has to be very fast

ch1 = Queue() 
ch2 = Queue()
ch3 = Queue() 
def girlboss(pkt: Packet):
    global ch1, ch2
    '''gatekeep, gaslight, girlboss'''
    # Packet isn't VOIP, we don't care about it
    if pkt.lastlayer().name != "SIP" and pkt.lastlayer().name != "RTP":
                return True
    src = pkt["IP"].src
    dst = pkt["IP"].dst
    # send full packet to analysis thread
    ch1.put(pkt)
    try:
        if ch2.get(block=True,timeout=0.1) == [src, dst, True]:
            #packet has been flagged for replacement
            # TODO: actually replace packet, don't just drop it
            return False
    except Empty:
        logging.error("Analysis thread taking too long! Overloaded?")
        # thread took too long, passing packet anyways
        pass
    return True

def analysis(channel1: Queue, channel2: Queue):
    logging.info("starting analysis thread")
    conversations = []
    
    while True:
        # Get packets from gatekeeper
        tmp = None
        try:
            tmp = channel1.get(block=True, timeout=0.05)
        except Empty:
            continue
        # Add new packet to list if there is one
        if tmp is not None:
            new = True
            # Check if this is part of an existing sessionRTP
            for con in conversations:
                stat = con.get_enforce(tmp)
                if stat == 1:
                    # Add the packet (UDP layer and above) to conversation object
                    con.add(tmp["UDP"])
                    # Tell main thread to let the packet through
                    channel2.put([tmp.src, tmp.dst, False])
                    new = False
                    break
                elif stat == 2:
                    #we're already enforcing, don't bother adding more packet data
                    #Tell main thread to manipulate data
                    channel2.put([tmp.src, tmp.dst, True])
                    new = False
                    break
            if new:
                conversations.append(conversation(tmp))



# Made up NIC names for now
## haha get it like nicknames but it's NICs i'm so funny
packetlog = scapy.sendrecv.bridge_and_sniff(if1='enp5s0',if2='enp5s1',xfrm12=girlboss)
packetlog.show()