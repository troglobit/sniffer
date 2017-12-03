
#include "sniffer.h"
#include <sqlite3.h>

static FILE *fp = NULL;
static sqlite3 *db = NULL;
static struct sockaddr_in source, dest;

static int callback(void *unused, int argc, char *argv[], char **col)
{
	int i;

	for(i = 0; i < argc; i++)
		printf("%s = %s\n", col[i], argv[i] ? argv[i] : "NULL");
	printf("\n");

	return 0;
}

int db_open(char *ifname)
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

	sql = "CREATE TABLE IF NOT EXISTS " DBTABLE "("
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

int db_close(void)
{
	if (db)
		sqlite3_close(db);
	if (fp)
		fclose(fp);
}

void db_insert(unsigned char *buf, int len)
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

