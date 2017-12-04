#ifndef SNIFFER_DB_H_
#define SNIFFER_DB_H_

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>		/* dirname() */
#include <netdb.h>
#include <paths.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define _PATH_SNIFFER "/var/lib/sniffer/"
#define DBTABLE       "FRAME"
#define FNBASE        "sniffer-%s"

#define LOG(fmt, args...) if (logfp) fprintf(logfp, fmt "\n", ##args)
#define DBG(fmt, args...) if (debug) LOG(fmt, ##args)

/*
 * Proposed output format, regardless of back-end:
 * id,len,dir,port,dmac,smac,vid,tagged,prio,ethtype,proto,sip,dip,sport,dport
 */
struct snif {
	uint8_t         dsa[8], port, dir;
	size_t          len;

	uint8_t         dmac[ETH_ALEN], smac[ETH_ALEN];
	uint16_t        ethtype;

	uint16_t        vid;
	uint8_t         prio, tagged;

	/* IP header (IPv4 only for now) */
	uint8_t         proto;
	struct in_addr  sip, dip;
	uint16_t        sport, dport;
};

extern int csv;
extern int mode;
extern int debug;
extern FILE *logfp;
extern char *__progname;

int   db_open   (char *ifname);
int   db_close  (void);
void  db_insert (struct snif *snif);

static inline char *get_path(char *fn, char *ext)
{
	char *dir;
	static char path[128];

	if (fn[0] == '/') {
		snprintf(path, sizeof(path), "%s%s", fn, ext);
	} else {
		if (getuid() > 0)
			snprintf(path, sizeof(path), _PATH_VARRUN "user/%d/" FNBASE "%s", getuid(), fn, ext);
		else
			snprintf(path, sizeof(path), _PATH_SNIFFER FNBASE "%s", fn, ext);
	}

	dir = strdup(path);
	if (!dir)
		return NULL;
	dir = dirname(dir);
	if (access(dir, W_OK))
		mkdir(dir, 0755);
	free(dir);

	return path;
}

#endif /* SNIFFER_DB_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
