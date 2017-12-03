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

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

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

#define DBTABLE "FRAME"
#define FNBASE  "sniffer-%s"

#define LOG(fmt, args...) if (logfp) fprintf(logfp, fmt, ##args)
#define DBG(fmt, args...) if (debug) LOG(fmt, ##args)

extern char *__progname;

static FILE *fp = NULL;
static FILE *logfp = NULL;
static sqlite3 *db = NULL;
static struct sockaddr_in source, dest;
static int debug = 0;
static int running = 1;
static unsigned long long tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0;

static char *get_path(char *ifname, char *ext)
{
	static char path[128];

	if (getuid() > 0)
		snprintf(path, sizeof(path), _PATH_VARRUN "user/%d/" FNBASE "%s",
			 getuid(), ifname, ext);
	else
		snprintf(path, sizeof(path), _PATH_VARRUN FNBASE "%s", ifname, ext);

	return path;
}

static void print_payload(unsigned char *data, int len)
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

static int callback(void *unused, int argc, char *argv[], char **col)
{
	int i;

	for(i = 0; i < argc; i++)
		printf("%s = %s\n", col[i], argv[i] ? argv[i] : "NULL");
	printf("\n");

	return 0;
}

static int db_open(char *ifname)
{
	int rc;
	char *path, *sql, *err;

	path = get_path(ifname, ".db");
	rc = sqlite3_open(path, &db);
	if (rc) {
		fprintf(stderr, "Failed opening db, %s: %s\n", path, sqlite3_errmsg(db));
		db = NULL;

		fp = fopen(get_path(ifname, ".txt"), "w");
		if (!fp)
			return 1;
	}

	sql = "CREATE TABLE " DBTABLE "("
		"ID INTEGER PRIMARY KEY AUTOINCREMENT,"
		"DMAC           TEXT    NOT NULL,"
		"SMAC           TEXT    NOT NULL,"
		"TYPE           TEXT    NOT NULL,"
		"SIP            TEXT    NOT NULL,"
		"DIP            TEXT    NOT NULL);";
//		"COUNT          INT     NOT NULL);";
	rc = sqlite3_exec(db, sql, callback, 0, &err);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", err);
		sqlite3_free(err);
		return 1;
	}
	warnx("db %s open, table %s created successfully", path, DBTABLE);

	return 0;
}

static int db_close(void)
{
	if (db)
		sqlite3_close(db);
	if (fp)
		fclose(fp);
}

static void db_add(unsigned char *buf, int len)
{
	struct ethhdr *eth = (struct ethhdr *)buf;
	unsigned short offset = 0, iphdrlen, ip_off, type;
	struct iphdr *iph;
	char dmac[20], smac[20], ethtype[10], sip[20], dip[20];

	type = ntohs(eth->h_proto);
	if (type == 0x0d5a) {
		offset = 12;
//		type = ntohs((eth + 10)->h_proto);
	}
	iph = (struct iphdr *)(buf + offset + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	/* Skip fragments ... */
	ip_off = ntohs(iph->frag_off);
	if (ip_off & 0x1fff)
		return;

	snprintf(dmac, sizeof(dmac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		 eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		 eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	snprintf(smac, sizeof(smac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		 eth->h_source[0], eth->h_source[1], eth->h_source[2],
		 eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	snprintf(ethtype, sizeof(ethtype), "0x%.4X", (unsigned short)type);
	snprintf(sip, sizeof(sip), "%15s", inet_ntoa(source.sin_addr));
	snprintf(dip, sizeof(dip), "%15s", inet_ntoa(dest.sin_addr));

	if (db) {
		int rc;
		char sql[256];
		char *err;

		snprintf(sql, sizeof(sql), "INSERT INTO " DBTABLE "(DMAC, SMAC, TYPE, SIP, DIP) "
			 "VALUES ('%s', '%s', '%s', '%s', '%s');", dmac, smac, ethtype, sip, dip);

		rc = sqlite3_exec(db, sql, callback, 0, &err);
		if (rc != SQLITE_OK) {
			fprintf(stderr, "SQL error: %s\n", err);
			sqlite3_free(err);
			return;
		}

		return;
	}

	warnx("db not open.");
	if (!fp) {
		warnx("log file not open.");
		return;
	}

	fprintf(fp, "[ DMAC: %s | ", dmac);
	fprintf(fp, "SMAC: %s | ", smac);
	fprintf(fp, "TYPE: %s | ", ethtype);
	fprintf(fp, "IPv%d | ", (unsigned int)iph->version);
	fprintf(fp, "SIP: %s |", sip);
	fprintf(fp, "DIP: %s ]\n", dip);
	fflush(fp);
}

static void print_ethernet_header(unsigned char *buf, int len)
{
	struct ethhdr *eth = (struct ethhdr *)buf;

	if (!logfp)
		return;

	LOG("\n");
	LOG("Ethernet Header\n");
	LOG("   |-Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_dest[0], eth->h_dest[1],
	    eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	LOG("   |-Source Address      : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_source[0], eth->h_source[1],
	    eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	LOG("   |-Protocol            : %u \n", (unsigned short)eth->h_proto);
}

static void print_ip_header(unsigned char *buf, int len)
{
	unsigned short iphdrlen;
	struct iphdr *iph;

	db_add(buf, len);

	print_ethernet_header(buf, len);

	if (!logfp)
		return;

	iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	LOG("\n");
	LOG("IP Header\n");
	LOG("   |-IP Version        : %d\n", (unsigned int)iph->version);
	LOG("   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
	LOG("   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
	LOG("   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
	LOG("   |-Identification    : %d\n", ntohs(iph->id));
//	LOG("   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
//	LOG("   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
//	LOG("   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	LOG("   |-TTL      : %d\n", (unsigned int)iph->ttl);
	LOG("   |-Protocol : %d\n", (unsigned int)iph->protocol);
	LOG("   |-Checksum : %d\n", ntohs(iph->check));
	LOG("   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
	LOG("   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
}

static void print_tcp_packet(unsigned char *buf, int len)
{
	unsigned short iphdrlen;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int hdrlen;

	LOG("\n\n***********************TCP Packet*************************\n");
	print_ip_header(buf, len);

	if (!logfp)
		return;

	iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	tcph = (struct tcphdr *)(buf + iphdrlen + sizeof(struct ethhdr));
	hdrlen = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

	LOG("\n");
	LOG("TCP Header\n");
	LOG("   |-Source Port      : %u\n", ntohs(tcph->source));
	LOG("   |-Destination Port : %u\n", ntohs(tcph->dest));
	LOG("   |-Sequence Number    : %u\n", ntohl(tcph->seq));
	LOG("   |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
	LOG("   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
//      LOG("   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
//      LOG("   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
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

static void print_udp_packet(unsigned char *buf, int len)
{
	unsigned short iphdrlen;
	struct iphdr *iph;
	struct udphdr *udph;
	int hdrlen;

	LOG("\n\n***********************UDP Packet*************************\n");
	print_ip_header(buf, len);

	if (!logfp)
		return;

	iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	udph = (struct udphdr *)(buf + iphdrlen + sizeof(struct ethhdr));
	hdrlen = sizeof(struct ethhdr) + iphdrlen + sizeof(udph);

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

static void print_icmp_packet(unsigned char *buf, int len)
{
	unsigned short iphdrlen;
	struct iphdr *iph;
	struct icmphdr *icmph;
	int hdrlen;

	LOG("\n\n***********************ICMP Packet*************************\n");
	print_ip_header(buf, len);

	if (!logfp)
		return;

	iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	icmph = (struct icmphdr *)(buf + iphdrlen + sizeof(struct ethhdr));
	hdrlen = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

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
//      LOG("   |-ID       : %d\n",ntohs(icmph->id));
//      LOG("   |-Sequence : %d\n",ntohs(icmph->sequence));
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

static void process(unsigned char *buf, int size)
{
	struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));

	total++;
	switch (iph->protocol) {
	case 1:			/* ICMP Protocol */
		icmp++;
		print_icmp_packet(buf, size);
		break;

	case 2:			/* IGMP Protocol */
		igmp++;
		print_ip_header(buf, size);
		break;

	case 6:			/* TCP Protocol */
		tcp++;
		print_tcp_packet(buf, size);
		break;

	case 17:		/* UDP Protocol */
		udp++;
		print_udp_packet(buf, size);
		break;

	default:		/* Some Other Protocol like ARP etc. */
		others++;
		break;
	}

	printf("\r\e[KTCP: %llu  UDP: %llu  ICMP: %llu  IGMP: %llu  Others: %llu  Total: %llu",
	       tcp, udp, icmp, igmp, others, total);
	fflush(stdout);
}

static void sigcb(int signo)
{
	DBG("Got signal %d\n", signo);
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
		"  -d       Enable debug messages to log\n"
		"  -h       This help text\n"
		"  -l FILE  Log all packets to FILE\n"
		"\n",
		__progname);

	return code;
}

int main(int argc, char *argv[])
{
	struct sockaddr sa;
	unsigned char *buf;
	socklen_t len;
	ssize_t sz;
	char *logfile = NULL, *ifname = NULL;
	int sd, ret;

	while ((ret = getopt(argc, argv, "dhl:")) != EOF) {
		switch (ret) {
		case 'd':
			debug = 1;
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

	printf("\e[?25l");
	printf("Starting %s on iface %s ...\n", __progname, ifname);
	signal(SIGTERM, sigcb);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
	signal(SIGINT, sigcb);
	signal(SIGHUP, SIG_IGN);

	buf = malloc(BUFSIZ);
	if (!buf)
		err(1, "Failed allocating buffer memory");

	sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sd < 0)
		err(1, "Failed opening RAW socket");

	ret = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
	if (ret < 0)
		err(1, "Failed binding socket to ifname %s", ifname);

	db_open(ifname);
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
