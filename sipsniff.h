/*
 SIPSniff - Version 1.3
 
 Written by Anton Kenov - akenov@gmail.com
 
 sipsniff.h - includes all needed headers and defines 
 
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 Used headers:
 
 stdio.h,stdlib.h,string.h - standard C headers
 pcap.h - libpcap header file - main lib for sniffing 
 linux/if_ether.h - defines ethhdr structure and IEEE 802.3 Ethernet constants
 linux/ip.h - defines iphdr structure (have additional IP constants)
 linux/udp - defines udphdr structure
 netinet/in.h - defines standard IPPROTO values and in_addr structure
 arpa/inet.h - defines function inet_ntoa()
*/


/*
 Must define UDP packet header size
 It seems it is always 8 bytes
*/
#define size_udphdr 8

/*EOF*/

