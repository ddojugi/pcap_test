#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int iplen, tcplen;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("dst mac : ");
    for(int i=0; i<6; i++)
	printf("%02x",packet[i]);
    printf("\n");
    printf("src mac : ");
    for(int i=6; i<12; i++)
	printf("%02x",packet[i]);
    printf("\n");
    if(packet[12]*256+packet[13] == 2048) 
    {
	   iplen = packet[14]%16;
	   printf("src ip : ");
	   for(int i=26; i<29; i++)
		printf("%d.",packet[i]);
	   printf("%d",packet[30]);
	   printf("\n");
	   printf("dst ip : ");
	   for(int i=30; i<33; i++)
		printf("%d.",packet[i]);
	   printf("%d",packet[34]);
	   printf("\n");

	   if(packet[23] == 6)
	   {
		tcplen = packet[26+iplen]/16;
		printf("src port : %d\n",(int)packet[14+iplen]+(int)packet[15+iplen]*256);
    		printf("dst port : %d\n",(int)packet[16+iplen]+(int)packet[17+iplen]*256);

		if(header->caplen > 18+iplen+tcplen)
			printf("DATA : ");
	   		for(int i=14+iplen+tcplen; i<46+iplen+tcplen; i++)
				printf("%02x ",packet[i]);
	   		printf("\n");
	   }
    }
  }

  pcap_close(handle);
  return 0;
}
