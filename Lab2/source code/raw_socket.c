#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#define BUFFER_MAX 2048

struct ARP
{
	unsigned short hw_type;
	unsigned short proto_type;
	unsigned char hw_addr_len;
	unsigned char proto_addr_len;
	unsigned short op_code;
	unsigned char sender_mac[6];
	unsigned char sender_ip[4];
	unsigned char receiver_mac[6];
	unsigned char receiver_ip[4]; 
};

int main(int argc, char* argv[])
{
    int sock_fd;
    int proto;
    int n_read;
    char buffer[BUFFER_MAX];
    char* eth_head;
    char* ip_head;
    char* tcp_head;
    char* udp_head;
    char* icmp_head;
    unsigned char* p;
    if ((sock_fd=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0)
    {
		printf("error create raw socket\n");
		return -1;
    } 

	struct ifreq ethreq;
	strncpy(ethreq.ifr_name, "ens33", IFNAMSIZ);
	ethreq.ifr_flags |= IFF_PROMISC;
	ioctl(sock_fd, SIOCGIFFLAGS, &ethreq);
	
	int No=1;
    while(1)
    {
		n_read=recvfrom(sock_fd, buffer, 2048, 0, NULL, NULL);
		if(n_read<42)
		{
			printf("n_read: %d\n", n_read);
	    	printf("error when recv msg\n"); 
			continue;
		}
		printf("****************************\n");
		printf("No: %d ", No);  No++;
		time_t timep;
		time (&timep);
		printf("%s", asctime(gmtime(&timep)));
		
		eth_head=buffer;

		printf("n_read: %d\n", n_read);
		printf("buffer:");
		unsigned char* buf=buffer;
		for (int i=0;i<n_read;i++){
			printf("%02x ", *buf);
			buf++;
		}
		printf("\n");

		p=eth_head;
		printf("MAC address: %.2x:%02x:%02x:%02x:%02x:%02x ==> %.2x:%02x:%02x:%02x:%02x:%02x\n",
			p[6],p[7],p[8],p[9],p[10],p[11],
			p[0],p[1],p[2],p[3],p[4],p[5]);

		// judge what kind of proto is
		char* p_proto=eth_head+12;
		short proto_type=((short)p_proto[0]<<8)+((short)p_proto[1]);
		printf("Protocol (in frame):");
		switch(proto_type){
			case 0x0800: printf("IPv4\n");break;
			case 0x0806: printf("ARP\n");break;
			case 0x8035: printf("RARP\n");break;
			case 0x8864: printf("PPPoE\n");break;
			case 0x86dd: printf("IPv6\n");break;
			case 0x8847: printf("MPLS\n");break;
			default: printf("Other Proto: 0x%x\n", proto_type);
		}

		if (proto_type==0x0800) // IP
		{
			ip_head=eth_head+14;
			p=ip_head+12;
			printf("IP: %d.%d.%d.%d ==> %d.%d.%d.%d\n",
				p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
			proto=(ip_head+9)[0];
			p=ip_head+12;
			printf("Protocol:");
			switch(proto){
				case IPPROTO_ICMP:printf("icmp\n");break;
				case IPPROTO_IGMP:printf("igmp\n");break;
				case IPPROTO_IPIP:printf("ipip\n");break;
        		case IPPROTO_TCP:printf("tcp\n");break;
 				case IPPROTO_UDP:printf("udp\n");break;
        		default:printf("Pls query yourself about: 0x%x\n", proto);
			} 
		}

		if (proto_type==0x0806 || proto_type==0x8035) // ARP/RARP
		{
			struct ARP* arp=eth_head+14;  
			switch(arp->op_code/256){
				case 1: printf("ARP request\n"); break;
				case 2: printf("ARP respons\n"); break;
				case 3: printf("RARP request\n"); break;
				case 4: printf("RARP respons\n"); break;
			} 
			p=arp->sender_mac;
			printf("Sender MAC: %.2x:%02x:%02x:%02x:%02x:%02x\n",
					p[0],p[1],p[2],p[3],p[4],p[5]);
			p=arp->sender_ip;
			printf("Sender IP: %d.%d.%d.%d\n",
					p[0],p[1],p[2],p[3]);
			p=arp->receiver_mac;
			printf("Reciever MAC: %.2x:%02x:%02x:%02x:%02x:%02x\n",
					p[0],p[1],p[2],p[3],p[4],p[5]);
			p=arp->receiver_ip;
			printf("Reciever IP: %d.%d.%d.%d\n",
					p[0],p[1],p[2],p[3]);
		}
		
    }
	return -1;
}
