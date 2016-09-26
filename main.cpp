#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include "type_header.h"

int main(int argc, char *argv[])
{
	pcap_t *handle = NULL;			/* Session handle */
	char *dev = NULL;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */


	bpf_u_int32 mask = 0;		/* Our netmask */
	bpf_u_int32 net = 0;		/* Our IP */


	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}


	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}


	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}


	int res = 0;
	struct pcap_pkthdr *header = NULL;	/* The header that pcap gives us */
	const u_char *packet = NULL;		/* The actual packet */

	while((res = pcap_next_ex(handle, &header, &packet)) >= 0)
	{
		if(res == 0)
			continue;
		
		struct libnet_ethernet_hdr *eth_hdr = NULL;
		u_int16_t eth_type = 0;

		eth_hdr = (libnet_ethernet_hdr *) packet;
		eth_type = ntohs(eth_hdr->ether_type);

		printf("Dest Mac : ");
		for (int i=0;i<6;i++)
			printf("%02x%c", eth_hdr->ether_dhost[i], (i!=5?':':'\n'));

		printf("Src Mac : ");
		for (int i=0;i<6;i++)
			printf("%02x%c", eth_hdr->ether_shost[i], (i!=5?':':'\n'));

		if (eth_type == ETHER_TYPE_IP)
		{
			struct libnet_ipv4_hdr *ipv4_hdr = NULL;
			u_int8_t ip_protocol = 0;
			struct in_addr src_ip, dst_ip;
			char src_ip_buf[20];
			char dst_ip_buf[20];
			

			ipv4_hdr = (libnet_ipv4_hdr *)((u_char *)eth_hdr + sizeof(struct libnet_ethernet_hdr));

			src_ip = ipv4_hdr->ip_src;
			dst_ip = ipv4_hdr->ip_dst;

			inet_ntop(AF_INET, &src_ip, src_ip_buf, sizeof(src_ip_buf));
			inet_ntop(AF_INET, &dst_ip, dst_ip_buf, sizeof(dst_ip_buf));

			printf("Src IP : %s\n", src_ip_buf);
			printf("Dst IP : %s\n", dst_ip_buf);

			ip_protocol = ipv4_hdr->ip_p;
			if(ip_protocol == IP_PROTOCOL_TCP)
			{
				struct libnet_tcp_hdr *tcp_hdr;
				u_int16_t src_port, dst_port;

				u_char *Data_Section;
				u_int32_t Data_Len;

				tcp_hdr = (libnet_tcp_hdr *)((u_char *)ipv4_hdr + sizeof(struct libnet_ipv4_hdr));

				src_port = ntohs(tcp_hdr->th_sport);
				dst_port = ntohs(tcp_hdr->th_dport);

				printf("Src Port : %d\n", src_port);
				printf("Dst Port : %d\n", dst_port);

				Data_Section = (u_char *)tcp_hdr + 4 * tcp_hdr->th_off;
				Data_Len = header->len - sizeof(struct libnet_ethernet_hdr) - sizeof(struct libnet_ipv4_hdr) - 4 * tcp_hdr->th_off;

				for(int i = 0 ; i < Data_Len ; i+=16)
				{
					int Cnt = i+16;
					if ( Cnt > Data_Len)
						Cnt = Data_Len;
					for(int j=i;j<Cnt;j++)
					{
						u_char tmp = *(Data_Section+j);
						printf("%02x ", tmp);
					}
					for(int j=1;j<=55-3*(Cnt-i);j++)
						printf(" ");
					for(int j=i;j<Cnt;j++)
					{
						char tmp = *(Data_Section+j);
						printf("%c", isprint((int)tmp)?tmp:'.');
					}
					printf("\n");
				}

			}
		}

		printf("\n\n");
		
	} 
	pcap_close(handle);
	return(0);
 }
