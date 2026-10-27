# This is Documentation for file "handle_udp"
## This file is very important so I think what I must write Documentation for him.


## Start from scratch: what is UDP?

**UDP**(User Datagram Protocol) — this is a way for computer to send data over the internet. Why need UDP? We have TCP, yeah? Yes! But TCP it's  like postman: u gived data fot him and he delivers it with 100% guarantee. But UDP it's like post: u will come and give a data but data can will lose or steal  (for example).


## What is inside QUIC initial packet? 
(well it's **first packet upon conect to server**. Like Tls-handshake in TCP)


Now we understanding structure of the QUIC Initial packet:

- 1st byte:
first byte doesn't means something one thing. It's very iformative byte. Every bit something mean. You know, it's like packet's passport.

Here is his structure:



| bit(s) | description |
| --- | --- |
| 7th bit | Is long header? (usually it's mean what packet is QUIC Initial) <br> 1 == yes, 0 - no |
| 6th bit | Fixed bit. Always equal 1. |
| 5th bit and 4th bit | This bytes means "**packet type**". <br> 0x00 - initial packet, 0x01 - Handshake etc... <br> So, in our case, must be equal 0 and 0. |
| 3rd bit and 2nd bit | This is "**reserved bits**". It's just bits that maybe will be use... but not now! So this bit just equal 0 and 0 |
| 1st bit and zero bit | QUIC is veeery economy. So this bytes means "**length of number packet**". Usually this bytes equal 0 and 0 (lenght of number of packet equal 1) or 1 and 1 (length == 4) |

- 2nd – 5th bytes:

This 4 bytes need for figure out which **version** have QUIC Initial packet. For example we might to understand what packet have "**QUIC v1**" Version(most popular today), or "**QUIC v2**" Version etc..

- 6th byte:

DCID Lenght (Destination Connection ID Length) — Thus is length DCID

- 7th - ... bytes:

DCID (Destination Connection ID) — This is random number (usually not less that 8 bytes) which indicates what sessions belongs packet (on Destination's sides). For example when u open 3 tab of sites u create 3 sessions. How ur computer might to understand which tab belongs some packet? Via DCID!

- End of DCID - end of DCID + 1:

SCID Length (Source Connection ID Length) — Just length of SCID (1 byte)

- End of DCID + 1 - End of DCID + 1 + SCID Length:

SCID (source ConnectionID) - This is like DCID but random number choice "source".

- End of SCID - End of SCID + 1:

Token length — length of the next field: "**token**"


> I won't use type of writing like:
>
> ● number of byte
>     What located in this byte — {definition}

- Token:

    Token — This is **proof** what client's address is already checked. 
    When client send 1st packet (initial) there is a field inside it "**Token = 0**". It's mean what packet WASN'T VERIFIED BY THE SERVERS. Server just reject packet (send packet **Retry**). Why? because it doesn't trust the address. Inside Retry packet server deposits itself bytes. 
    When client get answer from server they just resend initial-packet BUT with new token (instead of  1, token is geting another count recived by server).


- Length:

   Length — field what says how many bytes occupies fields "Packet number" and packet's payload.


- Packet Number:

