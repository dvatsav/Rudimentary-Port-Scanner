#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <chrono>
#include <ctime>

using namespace std;
struct in_addr dest_ip;
int response_type[65535];

int scan_type = 0;
int packet_protocol[] = {IPPROTO_TCP, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP};
int hdr_sizes[] = {sizeof(struct tcphdr), sizeof(struct tcphdr), sizeof(struct udphdr)};

struct 
pseudo_header
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	
	struct tcphdr tcp;
};

void *
udp_scans(void *ptr)
{
	int data_size;
	struct sockaddr saddr;
	socklen_t sock_len;

	unsigned char *buffer = (unsigned char *)malloc(65536);
	int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		fflush(stdout);
		return 0;
	}

	int rcvd = 0;
	while(1)
	{
		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &sock_len);
		fflush(stdout);
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			fflush(stdout);
			return 0;
		}

		struct iphdr *iphr = (struct iphdr *)buffer;
		int iplen = iphr->ihl << 2;

		struct icmp *icmp = (struct icmp *)(buffer + iplen);
		int icmp_len = 8; 
		struct iphdr *inner_ip = (struct iphdr *)(buffer + iplen + icmp_len);

		int inner_ip_len = inner_ip->ihl << 2;

		struct udphdr *udphr = (struct udphdr *)(buffer + iplen + icmp_len + inner_ip_len);

		if ((icmp->icmp_type == ICMP_UNREACH) && (icmp->icmp_code == ICMP_UNREACH_PORT))
		{
			cout << ntohs(udphr->dest) << "\n";
			fflush(stdout);
			response_type[ntohs(udphr->dest) - 1] = 1;
		}
	}
	
	close(sock_raw);
	fflush(stdout);
	return 0;
}

void *
tcp_scans(void *ptr)
{
	int data_size;
	struct sockaddr saddr;
	socklen_t sock_len;
	
	unsigned char *buffer = (unsigned char *)malloc(65536);
	int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	
	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		fflush(stdout);
		return 0;
	}
	int rcvd = 0;
	while(1)
	{
		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &sock_len);
		fflush(stdout);
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			fflush(stdout);
			return 0;
		}
		
		struct iphdr *ip_packet = (struct iphdr*)(buffer);
		struct sockaddr_in source_socket_address, dest_socket_address;
		memset(&source_socket_address, 0, sizeof(source_socket_address));
		source_socket_address.sin_addr.s_addr = ip_packet->saddr;
		memset(&dest_socket_address, 0, sizeof(dest_socket_address));
		dest_socket_address.sin_addr.s_addr = ip_packet->daddr;

		uint8_t protocol = ip_packet->protocol;
		if (protocol == IPPROTO_TCP)
		{
			struct tcphdr *tcp_packet = (struct tcphdr *)(buffer + (ip_packet->ihl<<2));
			
			if (tcp_packet->syn == 1 && tcp_packet->ack == 1)
			{
				response_type[ntohs(tcp_packet->source) - 1] = 2;
			}
			if (scan_type == 1)
			{
				response_type[ntohs(tcp_packet->source) - 1] = 1;	
			}
			
			
		}


		rcvd++;
	}
	
	close(sock_raw);
	fflush(stdout);
	return 0;
}

unsigned short
ip_checksum(unsigned short *addr, unsigned int count)
{
	unsigned long sum = 0;
	while (count > 1)
	{
		sum += *addr++;
		count -= 2;
	}
	
	if (count > 0)
	{
		sum += ((*addr) & htons(0xFF00));
	}
	
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}
	
	sum = ~sum;
	return ((unsigned short)sum);
}

uint16_t 
udp_checksum(struct udphdr *p_udp_header, size_t len, uint32_t src_addr, uint32_t dest_addr)
{
	const uint16_t *buf = (const uint16_t*)p_udp_header;
	uint16_t *ip_src = (uint16_t *)&src_addr, *ip_dst = (uint16_t *)&dest_addr;
	uint32_t sum;
	size_t length = len;


	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
		sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len & 1)
		sum += *((uint8_t*)buf);


	sum += *(ip_src++);
	sum += *ip_src;

	sum += *(ip_dst++);
	sum += *ip_dst;

	sum += htons(IPPROTO_UDP);
	sum += htons(length);


	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (uint16_t)~sum;
}

unsigned int
tcp_checksum(struct iphdr *iphr, unsigned short *ipPayload) 
{
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(iphr->tot_len) - (iphr->ihl<<2);
    struct tcphdr *tcphr = (struct tcphdr*)(ipPayload);
    sum += (iphr->saddr>>16)&0xFFFF;
    sum += (iphr->saddr)&0xFFFF;
    sum += (iphr->daddr>>16)&0xFFFF;
    sum += (iphr->daddr)&0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcpLen);
 
    tcphr->check = 0;
    while (tcpLen > 1) 
    {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    if(tcpLen > 0) 
    {
        sum += ((*ipPayload)&htons(0xFF00));
    }

	while (sum>>16) 
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}
	sum = ~sum;
    return (unsigned short)sum;
}

void 
build_ip_header(struct iphdr *iphr, char *packet, uint8_t protocol)
{
	iphr->ihl = 5;
	iphr->version = 4;
	iphr->tos = 16;
	iphr->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iphr->id = htons(34234);
	iphr->frag_off = htons(16384);
	iphr->ttl = 20;
	iphr->protocol = protocol;
	iphr->saddr = inet_addr("10.0.0.2");
	iphr->daddr = dest_ip.s_addr;
	iphr->check = 0;
}

void
build_tcp_header(struct tcphdr *tcphr)
{
	tcphr->source = htons(9494);
	tcphr->dest = htons(80);
	tcphr->seq = htonl(1105024978);
	tcphr->ack_seq = 0;
	tcphr->doff = sizeof(struct tcphdr) / 4;
	tcphr->fin = 0 | scan_type;
	tcphr->syn = 1 ^ scan_type;
	tcphr->rst = 0;
	tcphr->psh = 0;
	tcphr->ack = 0;
	tcphr->urg = 0;
	tcphr->window = htons(14600);
	tcphr->check = 0;
	tcphr->urg_ptr = 0;
}

void
build_udp_header(struct udphdr *udphr)
{
	udphr->source = htons(9494);
	udphr->dest = htons(22);
	udphr->len = htons(sizeof(struct udphdr));
}

int 
main(int argc, char *argv[])
{
	if (argc != 3 && argc != 4)
	{
		cout << "Usage: ./fmap <scan type> <IP Address> <Port (optional)>\n";
		exit(1);
	}

	if (!strcmp(argv[1], "-s"))
	{
		scan_type = 0;
	}
	else if (!strcmp(argv[1], "-f"))
	{
		scan_type = 1;
	}
	else if (!strcmp(argv[1], "-u"))
	{
		scan_type = 2;
	}
	else
	{
		cout << "Invalid Scan type. Available are:\n-u: UDP Scan\n-f: FIN Scan\n-s: SYN Scan\n";
		exit(1);
	}

	char *src_ip = argv[2];

	if (inet_addr(src_ip) != -1)
	{
		dest_ip.s_addr = inet_addr(src_ip);
	}
	else
	{
		fprintf(stderr, "%s\n", "Invalid IP Address");
		exit(1);
	}

	auto start = std::chrono::system_clock::now();
	std::time_t cur_time = std::chrono::system_clock::to_time_t(start);

	cout << "Starting Fmap 1.0 at " << std::ctime(&cur_time);
	
	cout << "Fmap scan report for " << argv[2] << "\n";

	int sock = socket(AF_INET, SOCK_RAW, packet_protocol[scan_type]);
	if (sock < 0)
	{
		perror("sock");
		exit(1);
	}

	char *packet = (char *)malloc(4096);
	memset(packet, 0, 4096);

	struct iphdr *iphr = (struct iphdr *)packet;
	struct tcphdr *tcphr = (struct tcphdr *)(packet + sizeof(struct ip));
	struct udphdr *udphr = (struct udphdr *)(packet + sizeof(struct iphdr));

	struct sockaddr_in dest;
	struct pseudo_header psh;

	build_ip_header(iphr, packet, packet_protocol[scan_type]);
	if (scan_type < 2)
		build_tcp_header(tcphr);
	if (scan_type == 2)
		build_udp_header(udphr);

	iphr->check = ip_checksum((unsigned short *)packet, iphr->tot_len >> 1);

	int one = 1;
	const int *val = &one;

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("setsockopt");
		exit(0);
	}

	void *targ = NULL;
	int  iret1;
	pthread_t tcp_scan, udp_scan;
	if (scan_type < 2)
	{
		if(pthread_create(&tcp_scan, NULL, tcp_scans, (void*)targ) < 0)
		{	
			perror("pthread_create");
			exit(0);
		}
	}	
	else
	{
		if(pthread_create(&udp_scan, NULL, udp_scans, (void*)targ) < 0)
		{	
			perror("pthread_create");
			exit(0);
		}
	}
		

	int port = 1;
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;
	int limit = 65535;
	if (argc == 4)
	{
		limit = atoi(argv[3]);
		port = atoi(argv[3]);
	}
	for(; port <= limit; port++)
	{
		response_type[port - 1] = 0;
		
		if (scan_type == 2)
		{
			udphr->dest = htons(port);
			udphr->check = 0;
			udphr->check = udp_checksum((struct udphdr *)(packet + sizeof(struct iphdr)), sizeof(udphdr), inet_addr("10.0.0.2"), dest_ip.s_addr);		
		}
		else
		{
			tcphr->dest = htons(port);
			tcphr->check = 0;
			
			
			psh.source_address = inet_addr("10.0.0.2");
			psh.dest_address = dest.sin_addr.s_addr;
			psh.placeholder = 0;
			psh.protocol = IPPROTO_TCP;
			psh.tcp_length = htons(sizeof(struct tcphdr));
		
			memcpy(&psh.tcp , tcphr, sizeof (struct tcphdr));
			
			tcphr->check = ip_checksum((unsigned short*)&psh, sizeof(struct pseudo_header));	
		}

		if (sendto(sock, packet, sizeof(struct iphdr) + hdr_sizes[scan_type], 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
		{
			printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
			exit(0);
		}

		sleep(0.01);

		if (scan_type == 2)
		{
			
			sleep(0.09);

			if (response_type[port - 1] == 0)
				if (sendto(sock, packet, sizeof(struct iphdr) + hdr_sizes[scan_type], 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
				{
					printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
					exit(0);
				}

			sleep(1);

			if (response_type[port - 1] == 0)
				if (sendto(sock, packet, sizeof(struct iphdr) + hdr_sizes[scan_type], 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
				{
					printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
					exit(0);
				}

			sleep(1);
		}

	}
	
	sleep(2);

	cout << "\nPORT" << "\t" << "STATE\n";
	if (argc == 4)
	{
		int i = atoi(argv[3]) - 1;
		if (response_type[i] == 0 && (scan_type == 1 || scan_type == 2) || response_type[i] == 2 && scan_type == 0)
		{
			if (scan_type == 2)
				cout << i + 1 << "/udp" << "\t" << "open|filtered" << "\n";
			else
				cout << i + 1 << "/tcp" << "\t" << "open" << "\n";
		}
		else
		{
			if (scan_type == 2)
				cout << i + 1 << "/udp" << "\t" << "closed" << "\n";
			else
				cout << i + 1 << "/tcp" << "\t" << "closed" << "\n";
		}

	}
	else
	{
		for (int i = 0; i < 65535; ++i)
		{
			if (response_type[i] == 0 && (scan_type == 1 || scan_type == 2) || response_type[i] == 2 && scan_type == 0)
			{
				if (scan_type == 2)
					cout << i + 1 << "/udp" << "\t" << "open|filtered" << "\n";
				else
					cout << i + 1 << "/tcp" << "\t" << "open" << "\n";
			}
		}
	}
		
	if (scan_type < 2)
		pthread_cancel(tcp_scan);
	else
		pthread_cancel(udp_scan);

	cout << "\nFmap done\n";

	return 0;
}