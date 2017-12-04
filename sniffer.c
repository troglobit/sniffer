/*
 * Copyright (c) 2017 Joachim Nilsson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "csv.h"
#include "sniffer.h"

int csv = 0;
int mode = 0;			/* Learning(0), Monitor(1) */
int debug = 0;
FILE *logfp = NULL;

static struct sockaddr_in source, dest;
static int running = 1;
static unsigned long long tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0;

static void print_payload(unsigned char *data, size_t len)
{
	int i, j;

	if (!logfp)
		return;

	for (i = 0; i < len; i++) {
		if (i != 0 && i % 16 == 0) {
			LOG("         ");
			for (j = i - 16; j < i; j++) {
				if (data[j] >= 32 && data[j] <= 128)
					LOG("%c", (unsigned char)data[j]);
				else
					LOG(".");
			}
			LOG("");
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

			LOG("");
		}
	}
}

static void print_ethernet_header(unsigned char *buf, size_t len)
{
	struct ethhdr *eth = (struct ethhdr *)buf;

	if (!logfp)
		return;

	LOG("");
	LOG("Ethernet Header");
	LOG("   |-Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", eth->h_dest[0], eth->h_dest[1],
	    eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	LOG("   |-Source Address      : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", eth->h_source[0], eth->h_source[1],
	    eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	LOG("   |-Protocol            : %u ", (unsigned short)eth->h_proto);
}

static void print_ip_header(unsigned char *buf, size_t len)
{
	unsigned short iphdrlen;
	struct iphdr *iph;

	print_ethernet_header(buf, len);

	if (!logfp)
		return;

	iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	LOG("");
	LOG("IP Header");
	LOG("   |-IP Version        : %d", (unsigned int)iph->version);
	LOG("   |-IP Header Length  : %d DWORDS or %d Bytes", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
	LOG("   |-Type Of Service   : %d", (unsigned int)iph->tos);
	LOG("   |-IP Total Length   : %d  Bytes(Size of Packet)", ntohs(iph->tot_len));
	LOG("   |-Identification    : %d", ntohs(iph->id));
//	LOG("   |-Reserved ZERO Field   : %d",(unsigned int)iphdr->ip_reserved_zero);
//	LOG("   |-Dont Fragment Field   : %d",(unsigned int)iphdr->ip_dont_fragment);
//	LOG("   |-More Fragment Field   : %d",(unsigned int)iphdr->ip_more_fragment);
	LOG("   |-TTL      : %d", (unsigned int)iph->ttl);
	LOG("   |-Protocol : %d", (unsigned int)iph->protocol);
	LOG("   |-Checksum : %d", ntohs(iph->check));
	LOG("   |-Source IP        : %s", inet_ntoa(source.sin_addr));
	LOG("   |-Destination IP   : %s", inet_ntoa(dest.sin_addr));
}

static void print_tcp_packet(unsigned char *buf, size_t len)
{
	unsigned short iphdrlen;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int hdrlen;

	LOG("\n\n***********************TCP Packet*************************");
	print_ip_header(buf, len);

	if (!logfp)
		return;

	iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	tcph = (struct tcphdr *)(buf + iphdrlen + sizeof(struct ethhdr));
	hdrlen = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

	LOG("");
	LOG("TCP Header");
	LOG("   |-Source Port      : %u", ntohs(tcph->source));
	LOG("   |-Destination Port : %u", ntohs(tcph->dest));
	LOG("   |-Sequence Number    : %u", ntohl(tcph->seq));
	LOG("   |-Acknowledge Number : %u", ntohl(tcph->ack_seq));
	LOG("   |-Header Length      : %d DWORDS or %d BYTES", (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
//      LOG("   |-CWR Flag : %d",(unsigned int)tcph->cwr);
//      LOG("   |-ECN Flag : %d",(unsigned int)tcph->ece);
	LOG("   |-Urgent Flag          : %d", (unsigned int)tcph->urg);
	LOG("   |-Acknowledgement Flag : %d", (unsigned int)tcph->ack);
	LOG("   |-Push Flag            : %d", (unsigned int)tcph->psh);
	LOG("   |-Reset Flag           : %d", (unsigned int)tcph->rst);
	LOG("   |-Synchronise Flag     : %d", (unsigned int)tcph->syn);
	LOG("   |-Finish Flag          : %d", (unsigned int)tcph->fin);
	LOG("   |-Window         : %d", ntohs(tcph->window));
	LOG("   |-Checksum       : %d", ntohs(tcph->check));
	LOG("   |-Urgent Pointer : %d", tcph->urg_ptr);
	LOG("");
	LOG("                        DATA Dump                         ");
	LOG("");

	LOG("IP Header");
	print_payload(buf, iphdrlen);

	LOG("TCP Header");
	print_payload(buf + iphdrlen, tcph->doff * 4);

	LOG("Data Payload");
	print_payload(buf + hdrlen, len - hdrlen);

	LOG("\n###########################################################");
}

static void print_udp_packet(unsigned char *buf, size_t len)
{
	unsigned short iphdrlen;
	struct iphdr *iph;
	struct udphdr *udph;
	int hdrlen;

	LOG("\n\n***********************UDP Packet*************************");
	print_ip_header(buf, len);

	if (!logfp)
		return;

	iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	udph = (struct udphdr *)(buf + iphdrlen + sizeof(struct ethhdr));
	hdrlen = sizeof(struct ethhdr) + iphdrlen + sizeof(udph);

	LOG("\nUDP Header");
	LOG("   |-Source Port      : %d", ntohs(udph->source));
	LOG("   |-Destination Port : %d", ntohs(udph->dest));
	LOG("   |-UDP Length       : %d", ntohs(udph->len));
	LOG("   |-UDP Checksum     : %d", ntohs(udph->check));

	LOG("");
	LOG("IP Header");
	print_payload(buf, iphdrlen);

	LOG("UDP Header");
	print_payload(buf + iphdrlen, sizeof(udph));

	LOG("Data Payload");

	/* Move the pointer ahead and reduce the size of string */
	print_payload(buf + hdrlen, len - hdrlen);

	LOG("\n###########################################################");
}

static void print_icmp_packet(unsigned char *buf, size_t len)
{
	unsigned short iphdrlen;
	struct iphdr *iph;
	struct icmphdr *icmph;
	int hdrlen;

	LOG("\n\n***********************ICMP Packet*************************");
	print_ip_header(buf, len);

	if (!logfp)
		return;

	iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	icmph = (struct icmphdr *)(buf + iphdrlen + sizeof(struct ethhdr));
	hdrlen = sizeof(struct ethhdr) + iphdrlen + sizeof(icmph);

	LOG("");
	LOG("ICMP Header");
	LOG("   |-Type : %d", (unsigned int)(icmph->type));

	if ((unsigned int)(icmph->type) == 11) {
		LOG("  (TTL Expired)");
	} else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY) {
		LOG("  (ICMP Echo Reply)");
	}

	LOG("   |-Code : %d", (unsigned int)(icmph->code));
	LOG("   |-Checksum : %d", ntohs(icmph->checksum));
//      LOG("   |-ID       : %d",ntohs(icmph->id));
//      LOG("   |-Sequence : %d",ntohs(icmph->sequence));
	LOG("");

	LOG("IP Header");
	print_payload(buf, iphdrlen);

	LOG("UDP Header");
	print_payload(buf + iphdrlen, sizeof(icmph));

	LOG("Data Payload");

	/* Move the pointer ahead and reduce the size of string */
	print_payload(buf + hdrlen, (len - hdrlen));

	LOG("\n###########################################################");
}

static int format(unsigned char *buf, size_t len, struct snif *snif)
{
	struct ethhdr *eth = (struct ethhdr *)buf;
	unsigned short offset = 0, iphdrlen, ip_off, type;
	struct iphdr *iph;
	struct tcphdr *tcph;

	memset(snif, 0, sizeof(*snif));
	snif->len = len;

	type = ntohs(eth->h_proto);
	if (type == 0xd5a) {
		uint32_t dsa;

		offset = 12;
		/* Skip DA+SA and four bytes 0x0d5a0000 */
		memcpy(snif->dsa, &buf[2 * ETH_ALEN + 4], sizeof(snif->dsa));
		type = ntohs((eth + 10)->h_proto);

		dsa  =  (snif->dsa[0] << 24) |
			(snif->dsa[1] << 16) |
			(snif->dsa[2] <<  8) |
			(snif->dsa[3] <<  0);
		snif->port   = (dsa >> 19) & 0x1f;
		snif->vid    =  dsa        & 0xfff;
		snif->dir    = (dsa >> 18) & 0x1;
		snif->tagged = (dsa >> 29) & 0x1;
		snif->prio   = (dsa >> 13) & 0x7;
	}

	iph = (struct iphdr *)(buf + offset + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	tcph = (struct tcphdr *)(buf + offset + iphdrlen + sizeof(struct ethhdr));

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	memcpy(snif->dmac, eth->h_dest, ETH_ALEN);
	memcpy(snif->smac, eth->h_source, ETH_ALEN);
	snif->ethtype = type;
	/* IPv4 */
	if (snif->ethtype == 0x0800) {
		/* Skip fragments ... */
		ip_off = ntohs(iph->frag_off);
		if (ip_off & 0x1fff)
			return 1;

		snif->proto = iph->protocol;
		snif->sip   = source.sin_addr;
		snif->dip   = dest.sin_addr;
		if (snif->proto == 6 || snif->proto == 17) {
			snif->sport = ntohs(tcph->source);
			snif->dport = ntohs(tcph->dest);
		}
	}

	return 0;
}

static void process(unsigned char *buf, size_t len)
{
	struct snif snif;
	struct iphdr *iph;

	iph = (struct iphdr *)(buf + sizeof(struct ethhdr));

	total++;
	switch (iph->protocol) {
	case 1:			/* ICMP Protocol */
		icmp++;
		print_icmp_packet(buf, len);
		break;

	case 2:			/* IGMP Protocol */
		igmp++;
		print_ip_header(buf, len);
		break;

	case 6:			/* TCP Protocol */
		tcp++;
		print_tcp_packet(buf, len);
		break;

	case 17:		/* UDP Protocol */
		udp++;
		print_udp_packet(buf, len);
		break;

	default:		/* Some Other Protocol like ARP etc. */
		others++;
		break;
	}

	if (!format(buf, len, &snif) && mode == 0) {
		if (csv)
			csv_insert(&snif);
		else
			db_insert(DB_GOOD, &snif);
	}

	printf("\r\e[KTCP: %llu  UDP: %llu  ICMP: %llu  IGMP: %llu  Others: %llu  Total: %llu",
	       tcp, udp, icmp, igmp, others, total);
	if (mode) {
		int found;

		found = db_find(DB_GOOD, &snif);
		printf(" => %s", found ? "OK" : "INTRUSION DETECTED!\n");
		if (!found)
			db_insert(DB_BAD, &snif);
	}
	fflush(stdout);
}

static void sigcb(int signo)
{
	DBG("Got signal %d", signo);
	if (signo == SIGHUP) {
		printf("\nChanging %s to MONITOR mode ...\n", __progname);
		mode = 1;
		return;
	}

	printf("\e[?25h");
	running = 0;
}

static int usage(int code)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s IFNAME\n"
		"\n"
		"Options:\n"
		"  -c       Enable CSV output, FILE.csv\n"
		"  -d       Enable debug messages to log\n"
		"  -f FILE  Set base FILE name for output data\n"
		"  -h       This help text\n"
		"  -l FILE  Log all packets to FILE\n"
		"\n",
		__progname);

	return code;
}

int main(int argc, char *argv[])
{
	struct sockaddr sa;
	struct ifreq ifr;
	unsigned char *buf;
	socklen_t len;
	ssize_t sz;
	char *fn = NULL, *logfile = NULL, *ifname = NULL;
	int sd, ret;

	while ((ret = getopt(argc, argv, "cdf:hl:")) != EOF) {
		switch (ret) {
		case 'c':
			csv = 1;
			break;

		case 'd':
			debug = 1;
			break;

		case 'f':
			fn = optarg;
			break;

		case 'h':
			return usage(0);

		case 'l':
			logfile = optarg;
			break;

		default:
			return usage(1);
		}
	}

	if (optind >= argc)
		return usage(1);
	ifname = argv[optind];

	if (!fn)
		fn = ifname;

	printf("\e[?25l");
	printf("Starting %s in LEARNING mode on iface %s ...\n", __progname, ifname);
	signal(SIGTERM, sigcb);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
	signal(SIGINT, sigcb);
	signal(SIGHUP, sigcb);

	buf = malloc(BUFSIZ);
	if (!buf)
		err(1, "Failed allocating buffer memory");

	sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sd < 0)
		err(1, "Failed opening RAW socket");

	ret = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
	if (ret < 0)
		err(1, "Failed binding socket to ifname %s", ifname);

	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);
	if (ioctl(sd, SIOCGIFFLAGS, &ifr)) {
		warn("Failed reading %s interface status", ifname);
	} else {
		ifr.ifr_flags |= IFF_PROMISC;
		if (ioctl(sd, SIOCSIFFLAGS, &ifr) < 0)
			warn("Failed setting %s in promiscuous mode", ifname);
	}

	if (csv)
		csv_open(fn);
	else
		db_open(fn);
	if (logfile) {
		logfp = fopen(logfile, "w");
		if (logfp == NULL)
			warn("Unable to create log file, %s", logfile);
	}

	while (running) {
		len = sizeof(sa);
		sz = recvfrom(sd, buf, BUFSIZ, 0, &sa, &len);
		if (sz < 0) {
			if (EINTR == errno)
				continue;
			err(1, "Failed receiving packets from %s", ifname ?: "network");
		}

		process(buf, sz);
	}

	close(sd);
	csv_close();
	db_close();
	printf("\nFinished.\n");

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
