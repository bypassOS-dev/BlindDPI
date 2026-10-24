# This is Documentation for file "handle_udp"
## This file is very important so I think what I must write Documentation for him.


## Start from scratch: what is UDP?

**UDP**(User Datagram Protocol) — this is a way for computer to send data over the internet. Why need UDP? We have TCP, yeah? Yes! But TCP it's  like postman: u gived data fot him and he delivers it with 100% guarantee. But UDP it's like post: u will come and give a data but data can will lose or steal  (for example).


## What is inside QUIC initial packet? 
(well it's **first packet upon conect to server**. Like Tls-handshake in TCP)


Now we understanding structure of the QUIC Initial packet:

- 1st byte:
first byte of QUIC initial packet need to server can  understand what usually THIS packet is first. 

Here is his structure:



| bit(s) | description |
| --- | --- |
| 7th bit | Is long header? (usually it's mean what packet is QUIC Initial) <br> 1 == yes, 0 - no |
| 6th bit | Fixed bit. Always equal 1. |
| 5th bit and 4th bit | This bytes means "**packet type**". <br> 0x00 - initial packet, 0x01 - Handshake etc... <br> So, in our case, must be equal 0 and 0. |
| 3rd bit and 2nd bit | This is "**reserved bits**". It's just bits that maybe will be use... but not now! So this bit just equal 0 and 0 |
| 1st bit and zero bit | QUIC is veeery economy. So this bytes means "**length of number packet**". Usually this bytes equal 0 and 0 (lenght of number of packet equal 1) or 1 and 1 (length == 4) |
