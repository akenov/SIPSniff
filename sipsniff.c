/*
 SIPSniff - Version 1.3
 
 Written by Anton Kenov - akenov@gmail.com
 
 sipsniff.c - main source file
 
*/

/*
 Include the rest of the source
 - header files
 - all defined functions
 - menu interface
*/
#include "sipsniff.h"
#include "functions.c"
#include "menu.c"

/* Define general variables */
char dev[32],errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle; //session handle
struct bpf_program fp; //compiled filter expression
char filter_exp[256]; //filter expr
bpf_u_int32 mask; // netmask number
bpf_u_int32 net; // network number
struct pcap_pkthdr header; //header of a packet
const u_char *packet; //the packet pointer


int main(int argc,char *argv[])
{ 
 /* Check for libpcap */
 if(strcmp(pcap_lib_version(),"libpcap version 0.9.4")<0)
 {
  printf("\nYour libpcap version is outdated!");
  printf("\nPlese update with new one and try again.");
  printf("\nYou can download libpcap form http://www.tcpdump.org\n\n");
 }
 else
 {
  /* All seems good - go on */
  printf("%s...good...let's sniff\n",pcap_lib_version());
  sleep(1);
 
  system("clear");
  menu(dev,filter_exp,handle,&fp,&mask,&net,errbuf);
 }
 return 0;
}

/*EOF*/
