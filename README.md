# Admiral Crunch
This program is designed for in-path VOIP inspection and tampering.
Written by Jacob Ellington.

## Don't Be Evil
This program was created as part of an assignment for CS4404 and may only be used for educational purposes on an **isolated network**.
Then again, if you've already gone through the trouble to get yourself in-path on a PBX system, you probably don't have much regard for authorial intent.

## Why
This exists to try to bypass 2FA over phone. It waits for an automated prompt for signing against our target and then injects packets containing DTMF frequencies for the pound symbol, authorizing the singin without user interaction. 

Since we of course don't want to actually attack any real accounts, we built our own analogue of the system with pyvoip which can be found in this organization's repos. 

## Overview of Operation
This program assumes you've gotten it in-path of a VOIP system. In our case, we accomplish this with some BGP shenanagans described in the other repos of this organization. Once we get VOIP traffic to route through us, we inspect all UDP packets going through us to check if it's VOIP, if the destination number is our target, and which VOIP session it belongs to. Each session is handled by a thread of Admiral Crunch. Once we detect a session initation, we assemble the RTP packets and attempt to decode voice data to see if the initiator says the words "ShueSec authenticator". If it detects this phrase, it injects packets containing the DTMF frequencies for the pound key into the stream coming from the client softphone.

## Technical Details (python rewrite)
