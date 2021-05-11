/*
 SIPSniff - Version 1.3
 
 Written by Anton Kenov - akenov@gmail.com
 
 function.c - collects all user-defined functions
 
*/

/*
 void read_str(char *str)
 
 Reads string from stdin to a char pointer
*/
void read_str(char *str,int len)
{
 char ch;
 int i;

 ch=getc(stdin);
 
 for(i=0;i<len;i++)
 {
  if(ch==10 || ch==13) break;
  *(str+i)=ch;
  ch=getc(stdin);
 } 
}

/*
 void print_hex_to_ascii(u_char *sip,int lenght,int offset)
 
 Function for printing from hex to ascii.
 It uses isprint() function to decide if
 the symbol is printable(if not - print '.')
*/
void print_hex_to_ascii(u_char *sip,int lenght,int offset)
{
 int i;
 int gap;
 u_char *ch;
 
 printf("%05d   ",offset);
 
 ch=sip;
 for(i=0;i<lenght;i++)
 {
  printf("%02x ",*ch);
  ch++;
  if(i==7) printf(" ");
 }
 
 if(lenght<8) printf(" ");
 
 if(lenght<16)
 {
  gap=16-lenght;
  for(i=0;i<gap;i++) printf("   ");
 }
 
 printf("   ");
 
 //ascii
 ch=sip;
 for(i=0;i<lenght;i++)
 {
  if(isprint(*ch)) printf("%c",*ch);
  else printf(".");
  ch++;
 }
 
 printf("\n");
}

/* Set default filter expression if not set any */
void set_default_filter(char *filter,char *exp)
{
 int i;
 
 if(!strlen(filter)) for(i=0;i<strlen(exp);i++) *(filter+i)=*(exp+i);
}

/*
 void print_wide_packet(u_char *sip,int lenght)
 
 Function for displaying packet info in ascii 
 symbols using print_hex_to_ascii() function.
 It displays info in order offset, hex, ascii
*/
void print_wide_packet(const unsigned char *sip,int lenght)
{
 int lenght_remain=lenght;
 int line_width=16;
 int line_lenght;
 int offset=0;
 u_char *ch=(u_char *)sip;
 
 
 if(lenght<=line_width)
 {
  print_hex_to_ascii(ch,line_lenght,offset);
  return;
 }
 
 for(;;)
 {
  line_lenght=line_width%lenght_remain;
  print_hex_to_ascii(ch,line_lenght,offset);
  lenght_remain=lenght_remain-line_lenght;
  ch=ch+line_lenght;
  offset=offset+line_width;
  if(lenght_remain<=line_width)
  {
   print_hex_to_ascii(ch,lenght_remain,offset);
   return;
  } 
 }

}

void print_sip_packet(const unsigned char *sip,const int size_sip)
{
 if(size_sip>0)
 {
 /*
  RFC 3261 defines SIP/2.0
  
  The following prinf() dumps on the screen
  the whole SIP packet content which is 
  ascii-formatted as it's defined in the RFC.
 */
  printf("\n%s",sip); 
 }
 else printf("Packet is empty!\n");  

}
/*
 Parse SIP header start-line
 and defines its values
*/
void sip_analyst(const unsigned char *sip,const int size_sip,const int mode)
{
 int i;
 unsigned char *ch=(unsigned char *)sip;
 char message[128],*m=message;
  
 /* Clear message buffer */
 memset(message,0,sizeof(message));

 /* Strip the first word to learn what type SIP message is */
 for(i=0;i<sizeof(message);i++)
 {
  if(*ch==' ') break;
  *(m+i)=*ch;
  ch++;
 }

 /*
   If it's SIP/2.0 => response,
   otherwise => request-method 
 */
 if(!strcmp(message,"SIP/2.0")) 
 {
  printf(" SIP Respone Message\n");
  if(mode==1) printf("  SIP Version:   %s\n",message);  

  /* Clear and position pointers*/
  memset(message,0,sizeof(message));
  m=message;
  ch++;
  
  /* Strip Status Code */
  for(i=0;i<sizeof(message);i++)
  {
   if(*ch==' ') break;
   *(m+i)=*ch;
   ch++;
  }
  if(mode==1) printf("  Status Code:   %s",message);
  
  /* Find out Status Code class */
  if(mode==1) switch(message[0])
  {
   case '1':
            printf(" - Provisional\n");
            break;
   case '2':
            printf(" - Success\n");
            break;
   case '3':
            printf(" - Redirection\n");
            break;
   case '4':
            printf(" - Client Error\n");
 	    break;
   case '5':
            printf(" - Server Error\n");
            break;
   case '6':
            printf(" - Global Error\n");
            break;
   default: 
            printf(" - Unknown class!\n");
            break;
  }

  /* Clear and position pointers*/
  memset(message,0,sizeof(message));
  m=message; 
  ch++;
  
  /* Strip Reason Phrase */
  for(i=0;i<sizeof(message);i++)
  {
   if(*ch=='\r')  break;
   *(m+i)=*ch;
   ch++;
  }
  if(mode==1) printf("  Reason Phrase: %s\n",message);
 
 
 }
 else 
 {
  printf(" SIP Request Message\n");
  if(mode==1) printf("  Method:      %s\n",message);

  /* Clear and position pointers*/
  memset(message,0,sizeof(message));
  m=message; 
  ch++;
  
  /* Strip Request-URI */
  for(i=0;i<sizeof(message);i++)
  {
   if(*ch==' ')  break;
   *(m+i)=*ch;
   ch++;
  }
  if(mode==1) printf("  Request-URI: %s\n",message);

  /* Clear and position pointers*/
  memset(message,0,sizeof(message));
  m=message; 
  ch++;
  
  /* Strip SIP Version */
  for(i=0;i<sizeof(message);i++)
  {
   if(*ch=='\r')  break;
   *(m+i)=*ch;
   ch++;
  }
  if(mode==1) printf("  SIP Version: %s\n",message);
 }
}
/*
 Dissect grabbed packed
 Remove Ethernet,IP,UDP header and print SIP message

 It is used by pcap_loop() for any matched packed
*/
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
 struct ethhdr *ethernet; // ethernet header p
 struct iphdr *ip; //ip header p
 struct udphdr *udp; // udp header
 unsigned char *sip; // sip packet
 struct in_addr ipsrc,ipdst; // store ip src & dst 

 char *smode;
 int mode;
 int size_ip;
 int size_udp;
 int size_sip;

 /* Return back to integer showmode value */ 
 smode=(char *)args;
 mode=atoi(smode);
 
 /*
  Prints packet lenght and time ; ctime have \n at the end
 */
 //printf("Captured lenght: %4d bytes | Lenght on wire: %4d\nTime: %s",
 //header->caplen,header->len,ctime((const time_t*)&header->ts.tv_sec)); 
 
 
 // ETHERNET decapsulation
 
 //get ethernet header
 ethernet=(struct ethhdr*)(packet);

 switch(ntohs(ethernet->h_proto))
 {
  case ETH_P_IP:
		    //printf("Protocol:     IP\n");
		    //go to the ip decapsulation process
		    break;
  case ETH_P_LOOP:
		    printf("\n\nProtocol: Ethernet Loopback packet\n");
		    printf("We are sorry but this packet type is not supported\n");
		    printf("by the application.\nExiting...");
		    return;
  case ETH_P_ARP:
		    printf("\n\nProtocol: Address Resolution packet\n");
		    printf("We are sorry but this packet type is not supported\n");
		    printf("by the application.\nExiting...");		    
		    return;
  case ETH_P_8021Q:
		    printf("\n\nProtocol: 802.1Q VLAN Extended Header\n");
		    printf("We are sorry but this packet type is not supported\n");
		    printf("by the application.\nExiting...");
		    return;
  default:
		    printf("\n\nProtocol: unknown\nExiting...");
		    return;
 }

 // IP decapsulation
 
 //get IP header
 ip=(struct iphdr*)(packet+ETH_HLEN);
 //calculate IP header size in bytes
 size_ip=ip->ihl*4;
 
 //placing IP addresses
 ipsrc.s_addr=ip->saddr;
 ipdst.s_addr=ip->daddr;
 

 if(size_ip<20)
 {
  printf("\n\nInvalid IP header length: %u bytes!\n",size_ip);
  return;
 };
 
 switch(ip->protocol)
 {
  case IPPROTO_UDP:
		    //printf("Protocol:     UDP\n");
		    //go to the udp decapsulation process
		    break;
  case IPPROTO_TCP:
		    printf("\n\nProtocol: TCP\n");
		    printf("We are sorry but this packet type is not supported\n");
		    printf("by the application.\nExiting...");
		    return;
  case IPPROTO_ICMP:
		    printf("\n\nProtocol: ICMP\n");
		    printf("We are sorry but this packet type is not supported\n");
		    printf("by the application.\nExiting...");
		    return;
  case IPPROTO_IP:
		    printf("\n\nProtocol: IP\n");
		    printf("We are sorry but this packet type is not supported\n");
		    printf("by the application.\nExiting...");
		    return;
  default:
		    printf("Protocol: unknown\nExiting...");
		    return;
 }

 //UDP decapsulation
 
 //get UDP header
 udp=(struct udphdr*)(packet+ETH_HLEN+size_ip);
 //total UDP packet size (header + data) in bytes
 size_udp=udp->len; 

 
 // SIP packet process
 
 //get SIP packet
 sip=(u_char *)(packet+ETH_HLEN+size_ip+size_udphdr);
 //calculate SIP packet size
 size_sip=ntohs(ip->tot_len)-(size_ip+size_udphdr);
 
 
 /* Short Showmode */
 if(mode==0)
 {
  printf(" %s:%d -> ",inet_ntoa(ipsrc),ntohs(udp->source));
  printf("%s:%d\n",inet_ntoa(ipdst),ntohs(udp->dest));
  sip_analyst(sip,size_sip,mode); 
  printf("\n");
 }
 /* Normal Showmode */
 if(mode==1)
 {
  printf(" MACs ");
  printf("%s -> ",ether_ntoa(ethernet->h_source));
  printf("%s\n",ether_ntoa(ethernet->h_dest)); 
  printf(" %s:%d -> ",inet_ntoa(ipsrc),ntohs(udp->source));
  printf("%s:%d\n",inet_ntoa(ipdst),ntohs(udp->dest));
  sip_analyst(sip,size_sip,mode); 
  printf("\n");
 }
 /* Entended Showmode */
 if(mode==2)
 {
  printf(" MACs ");
  printf("%s -> ",ether_ntoa(ethernet->h_source));
  printf("%s\n",ether_ntoa(ethernet->h_dest)); 
  printf(" %s:%d -> ",inet_ntoa(ipsrc),ntohs(udp->source));
  printf("%s:%d\n",inet_ntoa(ipdst),ntohs(udp->dest));
  printf(" SIP packet size: %u bytes\n",size_sip);
  print_sip_packet(sip,size_sip);
 }
 /* HEX Showmode */
 if(mode==3)
 {
  print_wide_packet(sip,size_sip);
  printf("\n");
 }
 

 /*
  It's one packet structure so the part of info from previous packet
  which is not overwritten in the new one will be displayed as it's
  a part of the new packet
  
  Clear the whole packet by setting every byte to 0.
 */ 
 memset((unsigned char *)packet,0,header->len);

}

/*
 Do actual sniffing
 - map showmode
 - define handle / pcap_open_line()
 - check for Ethernet IEEE 802.3 environment
 - set default filter
 - mangle filter / pcap_compile()
 - install filter / pcap_setfilter()
 - sniff for packets / pcap_loop()
 - free used resources
*/
int capture(const char *dev,char *filter,const int num_packets,const int mode,
pcap_t *handle,struct bpf_program *fp,bpf_u_int32 *mask,bpf_u_int32 *net,char *errbuf)
{
 char smode[2];
 u_char *smodeptr;
 
 /* Map mode to be passed as an argument in got_packet() */
 switch(mode)
 {
  case 0:strcpy(smode,"0");
         break;
  case 1:strcpy(smode,"1");
         break;
  case 2:strcpy(smode,"2");
         break;
  case 3:strcpy(smode,"3");
         break; 
 } 
 smodeptr=(u_char *)smode;

 handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
 if(handle==NULL)
 {
  printf("Couldn't open device %s: %s\n",dev,errbuf);
  return(2);
 } 
 
 if(pcap_datalink(handle)!=DLT_EN10MB)
 {
  printf("%s is not Ethernet\n",dev);
  printf("We are sorry but this application is made\nto work only on IEEE 802.3 Ethernet environment.");
  return(2);
 }
 
 /* set default filter for SIP sniffing */
 set_default_filter(filter,"udp and port 5060");
 
 if(pcap_compile(handle,fp,filter,0,*net)==-1)
 {
  printf("Couldn't parse filter %s: %s\n",filter,pcap_geterr(handle));
  return(2);
 }
 
 if(pcap_setfilter(handle,fp)==-1)
 {
  printf("Couldn't install filter %s: %s\n",filter,pcap_geterr(handle));
  return(2);
 }

 pcap_loop(handle,num_packets,got_packet,smodeptr);

 /* free the memory used by pcap */
 pcap_freecode(fp);
 pcap_close(handle);

}

/*EOF*/
