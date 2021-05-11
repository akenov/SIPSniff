/*
 SIPSniff - Version 1.3
 
 Written by Anton Kenov - akenov@gmail.com
 
 menu.c - defines user's menu

*/

/*
 Show all available network devices
 good for sniffing by libpcap
*/
void get_alldevices(void)
{
 pcap_if_t *alldevsp;
 char errbuf[PCAP_ERRBUF_SIZE];

 if(pcap_findalldevs(&alldevsp,errbuf)==-1)
 {
  printf("Error occured trying to find system devices: %s\n",errbuf);
  return;
 }
 
 printf(" Available devices: [ ");

 for(;;)
 {
  if(strcmp(alldevsp->name,"any")) printf("%s ",alldevsp->name); 
  if(alldevsp->next==NULL) break;
  alldevsp=alldevsp->next;
 }
 
 printf("auto ]\n");
 
 pcap_freealldevs(alldevsp);
}
/*
 Read user input
*/
void read_cmd(char *cmd)
{
 char ch;
 int i;
 
 i=0; 
 ch=getc(stdin);
 
 /* Read command */
 for(;;)
 {
  if(ch==32) break;
  if(ch==10 || ch==13) return;
  *(cmd+i)=ch;
  i++;
  ch=getc(stdin);
 }
 
 i=0; 
 ch=getc(stdin);
 
 /* Read arguments (optional) */
 for(;;)
 {
  if(ch==10 || ch==13) break;
  *(cmd+256+i)=ch;
  i++;
  ch=getc(stdin);
 }

}
/*
 Menu interface
*/
int menu(char *dev,char *filter,pcap_t *handle,struct bpf_program *fp,
bpf_u_int32 *mask,bpf_u_int32 *net,char *errbuf)
{
 char cmd_lines[2][256],*cmd;
 int num,mode,unknown,devset,smchk;
 struct in_addr ip;
 
 cmd=(char *)cmd_lines;
 devset=0; /* Is the device set */
 *mask=0;
 *net=0;
 mode=1; /* Set normal showmode */
 
 for(;;)
 {
  printf("SIPSniff > ");
  
  /* Check for unknown command */
  unknown=1;
  /* Clear the array fot the next use */
  memset(cmd_lines,0,sizeof(cmd_lines));
 
  /* Read commands */
  read_cmd(cmd);
 
  /* device command */
  if(!strcmp(cmd,"device"))
  {
   unknown=0;
   if(strlen(cmd+256))
   {
    if(!strcmp(cmd+256,"auto"))
    {
     dev=pcap_lookupdev(errbuf);
     if(dev==NULL)
     {
      printf(" Can't find valid network device\n");
      break;
     }     
    }
    else strcpy(dev,cmd+256);

    printf(" Device set to %s\n",dev); 
    devset=1;

    if(pcap_lookupnet(dev,net,mask,errbuf)==-1)
    {
     printf(" Can't get nemask for device %s\n",dev);
     *net=0;
     *mask=0;
      break;
    }
   }
   else
   {
    printf(" Usage : device device-name\n");
    printf(" Current device : ");
    if(strlen(dev)) printf("%s\n",dev);
    else printf("not set\n");
    get_alldevices();
   }
  }

  /* filter command */
  if(!strcmp(cmd,"filter"))
  {
   unknown=0;
   if(strlen(cmd+256))
   {
    strcpy(filter,cmd+256);
    printf(" Filter set to %s\n",filter);
   }
   else
   {
    printf(" Usage : filter filter-expression\n");
    printf(" Current filter : ");
    if(strlen(filter)) printf("%s\n",filter);
    else printf("not set\n");
   }
  }
  
  
  /* netmask command */
  if(!strcmp(cmd,"netmask"))
  {
   unknown=0;
   if(strlen(cmd+256))
   {
    inet_aton(cmd+256,&ip);
    *mask=ip.s_addr;
    printf(" Netmask set to %s\n",inet_ntoa(ip));
   }
   else
   {
    printf(" Usage : netmask network-mask\n");
    printf(" Current netmask : ");
    if(*mask) 
    {
     ip.s_addr=*mask;
     printf("%s\n",inet_ntoa(ip));
    }
    else printf("not set\n");
   }
  }
  
  /* status command */
  if(!strcmp(cmd,"status"))
  {
   unknown=0;
   /* Show device status */
   printf(" Device : ");
   if(strlen(dev)) 
   {
    printf("%s\n",dev);
    ip.s_addr=*mask;
    printf(" Netmask : %s\n",inet_ntoa(ip));
    ip.s_addr=*net;
    printf(" Network : %s\n",inet_ntoa(ip));
   }
   else printf("not set\n");

   /* Show filter status */   
   printf(" Filter : ");  
   if(strlen(filter)) printf("%s\n",filter);
   else printf("default (udp and port 5060)\n");

   /* Show showmode status */
   printf(" Showmode : ");
   switch(mode)
   {
    case 0:printf("short\n");
           break;
    case 1:printf("normal\n");
           break;
    case 2:printf("extended\n");
           break;
    case 3:printf("hex\n");
           break;
    default: printf("unknown!\n");
   }
   
  }
  
  /* showmode command */
  if(!strcmp(cmd,"showmode"))
  {
   unknown=0;
   if(strlen(cmd+256))
   {
    smchk=1;
    if(!strcmp(cmd+256,"short"))
    {
     mode=0;
     smchk=0;
     printf(" Showmode set to short\n");
    }
    if(!strcmp(cmd+256,"normal"))
    {
     mode=1;
     smchk=0;
     printf(" Showmode set to normal\n");
    }
    if(!strcmp(cmd+256,"extended"))
    {
     mode=2;
     smchk=0;
     printf(" Showmode set to extended\n");
    }
    if(!strcmp(cmd+256,"hex"))
    {
     mode=3;
     smchk=0;
     printf(" Showmode set to hex\n");
    }
    if(smchk)
    {
     printf(" Error: Unknown Show Mode!\n");
     printf(" Possible showmodes : [ short normal extended hex ]\n");
    } 
   }
   else
   {
    printf(" Usage : showmode mode\n");
    printf(" Current showmode : ");
    switch(mode)
    {
     case 0:printf("short\n");
    	    break;
     case 1:printf("normal\n");
    	    break;
     case 2:printf("extended\n");
    	    break;
     case 3:printf("hex\n");
            break;
     default: printf("unknown!\n");
    }
    printf(" Possible showmodes : [ short normal extended hex ]\n");
   }
  }
  
  /* capture command */
  if(!strcmp(cmd,"capture"))
  {
   unknown=0;
   if(strlen(cmd+256))
   {
    /* Convert ASCII to integer */
    num=atoi(cmd+256);
    if(devset) capture(dev,filter,num,mode,handle,fp,mask,net,errbuf);
    else printf(" You must enter device for sniffing!\n");
   }
   else
   {
    printf(" Usage : capture number-of-packets\n");
    printf(" Example : 'capture 10' or 'capture -1' to infinity\n");
   }
  }

  /* help command */
  if(!strcmp(cmd,"help"))
  {
   unknown=0;
   printf("\nSIPSniff Version 1.3\n");
   printf("\nCommands:\n\n");
   
   printf(" device    - Can set, change and show current used device\n");
   printf(" netmask   - Can change the netmask of the current used device\n");
   printf(" filter    - Can change default set filter (udp and port 5060)\n");
   printf(" showmode  - Can be short, normal, extended or hex\n");
   printf(" status    - Shows current system configuration\n");
   printf(" capture   - Actual sniffing, must know how many packets to capture\n");
   printf(" about     - Prints simple information for the program\n");
   printf(" help      - Prints this screen\n");
   printf(" exit/quit - Exits the program\n");  
   
   printf("\nFor more information about SIPSniff please read the README file.\n\n");
  }
  
  /* about command */
  if(!strcmp(cmd,"about"))
  {
   unknown=0;
   printf("\nSIPSniff Version 1.3");
   printf("\nWritten by Anton Kenov");
   printf("\nemail: akenov@gmail.com\n\n");
  }

  /* exit/quit commands */
  if(!strcmp(cmd,"exit")) break;
  if(!strcmp(cmd,"quit")) break;

  /* unknown command */
  if(unknown && strlen(cmd)) printf(" %s : command not found\n",cmd);
 }
}

/* EOF */
