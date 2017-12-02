#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define LOG(args...) if (logfile) fprintf(logfile, ##args)

FILE *logfile;
struct sockaddr_in source, dest;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i, j;

void print_payload(unsigned char *data, int len)
{
	int i, j;

	for (i = 0; i < len; i++) {
		if (i != 0 && i % 16 == 0) {
			LOG("         ");
			for (j = i - 16; j < i; j++) {
				if (data[j] >= 32 && data[j] <= 128)
					LOG("%c", (unsigned char)data[j]);
				else
					LOG(".");
			}
			LOG("\n");
		}

		if (i % 16 == 0)
			LOG("   ");
		LOG(" %02X", (unsigned int)data[i]);

		if (i == len - 1) {
			for (j = 0; j < 15 - i % 16; j++)
				LOG("   ");
			LOG("         ");

			for (j = i - i % 16; j <= i; j++) {
				if (data[j] >= 32 && data[j] <= 128)
					LOG("%c", (unsigned char)data[j]);
				else
					LOG(".");
			}

			LOG("\n");
		}
	}
}

void print_ethernet_header(unsigned char *buf, int len)
{
	struct ethhdr *eth = (struct ethhdr *)buf;

	LOG("\n");
	LOG("Ethernet Header\n");
	LOG("   |-Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_dest[0], eth->h_dest[1],
		eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	LOG("   |-Source Address      : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_source[0], eth->h_source[1],
		eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	LOG("   |-Protocol            : %u \n", (unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char *buf, int len)
{
	unsigned short iphdrlen;
	struct iphdr *iph;

	print_ethernet_header(buf, len);

	iph      = (struct iphdr *)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	LOG("\n");
	LOG("IP Header\n");
	LOG("   |-IP Version        : %d\n", (unsigned int)iph->version);
	LOG("   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl,
		((unsigned int)(iph->ihl)) * 4);
	LOG("   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
	LOG("   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
	LOG("   |-Identification    : %d\n", ntohs(iph->id));
//	fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
//	fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
//	fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	LOG("   |-TTL      : %d\n", (unsigned int)iph->ttl);
	LOG("   |-Protocol : %d\n", (unsigned int)iph->protocol);
	LOG("   |-Checksum : %d\n", ntohs(iph->check));
	LOG("   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
	LOG("   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char *buf, int len)
{
	unsigned short iphdrlen;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int hdrlen;

	iph      = (struct iphdr *)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	tcph     = (struct tcphdr *)(buf + iphdrlen + sizeof(struct ethhdr));
	hdrlen   = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

	LOG("\n\n***********************TCP Packet*************************\n");

	print_ip_header(buf, len);

	LOG("\n");
	LOG("TCP Header\n");
	LOG("   |-Source Port      : %u\n", ntohs(tcph->source));
	LOG("   |-Destination Port : %u\n", ntohs(tcph->dest));
	LOG("   |-Sequence Number    : %u\n", ntohl(tcph->seq));
	LOG("   |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
	LOG("   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcph->doff,
		(unsigned int)tcph->doff * 4);
//	fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
//	fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	LOG("   |-Urgent Flag          : %d\n", (unsigned int)tcph->urg);
	LOG("   |-Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
	LOG("   |-Push Flag            : %d\n", (unsigned int)tcph->psh);
	LOG("   |-Reset Flag           : %d\n", (unsigned int)tcph->rst);
	LOG("   |-Synchronise Flag     : %d\n", (unsigned int)tcph->syn);
	LOG("   |-Finish Flag          : %d\n", (unsigned int)tcph->fin);
	LOG("   |-Window         : %d\n", ntohs(tcph->window));
	LOG("   |-Checksum       : %d\n", ntohs(tcph->check));
	LOG("   |-Urgent Pointer : %d\n", tcph->urg_ptr);
	LOG("\n");
	LOG("                        DATA Dump                         ");
	LOG("\n");

	LOG("IP Header\n");
	print_payload(buf, iphdrlen);

	LOG("TCP Header\n");
	print_payload(buf + iphdrlen, tcph->doff * 4);

	LOG("Data Payload\n");
	print_payload(buf + hdrlen, len - hdrlen);

	LOG("\n###########################################################");
}

void print_udp_packet(unsigned char *buf, int len)
{
	unsigned short iphdrlen;
	struct iphdr *iph;
	struct udphdr *udph;
	int hdrlen;

	iph      = (struct iphdr *)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	udph     = (struct udphdr *)(buf + iphdrlen + sizeof(struct ethhdr));
	hdrlen   = sizeof(struct ethhdr) + iphdrlen + sizeof(udph);

	LOG("\n\n***********************UDP Packet*************************\n");

	print_ip_header(buf, len);

	LOG("\nUDP Header\n");
	LOG("   |-Source Port      : %d\n", ntohs(udph->source));
	LOG("   |-Destination Port : %d\n", ntohs(udph->dest));
	LOG("   |-UDP Length       : %d\n", ntohs(udph->len));
	LOG("   |-UDP Checksum     : %d\n", ntohs(udph->check));

	LOG("\n");
	LOG("IP Header\n");
	print_payload(buf, iphdrlen);

	LOG("UDP Header\n");
	print_payload(buf + iphdrlen, sizeof udph);

	LOG("Data Payload\n");

	/* Move the pointer ahead and reduce the size of string */
	print_payload(buf + hdrlen, len - hdrlen);

	LOG("\n###########################################################");
}

void print_icmp_packet(unsigned char *buf, int len)
{
	unsigned short iphdrlen;
	struct iphdr *iph;
	struct icmphdr *icmph;
	int hdrlen;

	iph      = (struct iphdr *)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	icmph    = (struct icmphdr *)(buf + iphdrlen + sizeof(struct ethhdr));
	hdrlen   = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

	LOG("\n\n***********************ICMP Packet*************************\n");

	print_ip_header(buf, len);

	LOG("\n");

	LOG("ICMP Header\n");
	LOG("   |-Type : %d", (unsigned int)(icmph->type));

	if ((unsigned int)(icmph->type) == 11) {
		LOG("  (TTL Expired)\n");
	} else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY) {
		LOG("  (ICMP Echo Reply)\n");
	}

	LOG("   |-Code : %d\n", (unsigned int)(icmph->code));
	LOG("   |-Checksum : %d\n", ntohs(icmph->checksum));
//	fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
//	fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
	LOG("\n");

	LOG("IP Header\n");
	print_payload(buf, iphdrlen);

	LOG("UDP Header\n");
	print_payload(buf + iphdrlen, sizeof icmph);

	LOG("Data Payload\n");

	/* Move the pointer ahead and reduce the size of string */
	print_payload(buf + hdrlen, (len - hdrlen));

	LOG("\n###########################################################");
}

void process(unsigned char *buf, int size)
{
	struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));

	++total;
	switch (iph->protocol)
	{
	case 1:		/* ICMP Protocol */
		++icmp;
		print_icmp_packet(buf, size);
		break;

	case 2:		/* IGMP Protocol */
		++igmp;
		break;

	case 6:		/* TCP Protocol */
		++tcp;
		print_tcp_packet(buf, size);
		break;

	case 17:	/* UDP Protocol */
		++udp;
		print_udp_packet(buf, size);
		break;

	default:	/* Some Other Protocol like ARP etc. */
		++others;
		break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp, udp, icmp, igmp, others, total);
}

int main(int argc, char *argv[])
{
	struct sockaddr sa;
	unsigned char *buf;
	socklen_t len;
	ssize_t sz;
	char *ifname = NULL;
	int sd, ret;

	logfile = fopen("log.txt", "w");
	if (logfile == NULL) {
		printf("Unable to create log.txt file.");
	}
	printf("Starting...\n");

	buf = malloc(BUFSIZ);
	if (!buf)
		err(1, "Failed allocating buffer memory");

	sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sd < 0)
		err(1, "Failed opening RAW socket");

	if (argc > 1) {
		ifname = argv[1];
		ret = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
		if (ret < 0)
			err(1, "Failed binding socket to ifname %s", ifname);
	}

	while (1) {
		len = sizeof(sa);
		sz = recvfrom(sd, buf, BUFSIZ, 0, &sa, &len);
		if (sz < 0)
			err(1, "Failed receiving packets from %s", ifname ?: "network");

		process(buf, sz);
	}
	close(sd);
	printf("Finished");

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
