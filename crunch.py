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
        try:
            tmp = channel1.get(block=True, timeout=0.05)
        except Empty:
            continue
            




packetlog = scapy.sendrecv.bridge_and_sniff(if1='enp5s0',if2='enp5s1',xfrm12=girlboss)
packetlog.show()