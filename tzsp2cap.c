//tzsp2cap - Convert a tzsp stream received on UDP port 37008 to PCAP file
//Author: Troy Nelson
//Date: July 19th, 2012
//Email: t9n3 'at' hotmail 'dot' com
//Reference: http://www.cet.nau.edu/~mc8/Socket/Tutorials/section1.html
//Compile: gcc -lpcap tzsp2cap.c -o tzsp2cap

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

int running = 1;

void sigterm(int signo)
{
    running = 0;   //used to close pcap file gracefully
}

void modPcapHeader(char* filename)
{
//Since the TZSP protocol is being sent over Ethernet
//and the protocol inside TZSP is WiFi we need to
//modify the pcap header. An 'i' is inserted in the
//header to indicate WiFi
   FILE* f;
   if((f=fopen(filename, "r+")) == NULL){
      printf("%s\n",(char*)strerror(errno));
      exit(1);
   }
   int i;
   for(i=0;i<20;i++)
      fgetc(f);
   fputc('i',f);
   fclose(f);
}

int main(int argc,char **argv)
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    const u_char *new_Packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;    /* net/ethernet.h */
    struct bpf_program fp;        /* hold compiled program */
    bpf_u_int32 maskp;            /* subnet mask */
    bpf_u_int32 netp;             /* ip */
 
    if(argc < 3 || argc > 4){
        fprintf(stdout, "Usage: %s <interface> <output file> [<wifi-flag>]\n",argv[0]);
        fprintf(stdout, "Example:\n");
        fprintf(stdout, "If TZSP encapsulated data originated from Ethernet: %s eth0 test.cap\n",argv[0]);
        fprintf(stdout, "If TZSP encapsulated data originated from WiFi    : %s eth0 test.cap 1\n",argv[0]);
        return 0;
    }

    signal(SIGTERM, sigterm);
    signal(SIGHUP, sigterm);
    signal(SIGINT, sigterm);

 
    /* open device for reading in promiscuous mode */
    descr = pcap_open_live(argv[1], BUFSIZ, 1,-1, errbuf);
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }
 
    /* Now we'll compile the filter expression*/
//    if(pcap_compile(descr, &fp, argv[1], 0, netp) == -1) {
    if(pcap_compile(descr, &fp, "udp port 37008", 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }
 
    /* set the filter */
    if(pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }
 
    printf("Stop capture by pressing Ctrl-C...\n");
    pcap_dumper_t* myDumpFile = pcap_dump_open(descr, argv[2]);
    while(1)
    {
       packet = pcap_next(descr,&hdr);
       if (packet != NULL)
       {
          new_Packet = packet + 63;     //remove tzsp protocol
      hdr.len -= 63;         //shorten length to write to pcap file
          pcap_dump((u_char*)myDumpFile,&hdr,(const u_char*)new_Packet); //put packet in pcap file
       }
   if (running == 0)
   {
      pcap_dump_close(myDumpFile);   //close pcap file gracefully
      if ( ((char) *argv[3]) == '1')  //if TZSP data came from a wifi source
         modPcapHeader(argv[2]); //modify the pcap file header to WiFi
      exit(0);
   }
    }
    return 0;
}
