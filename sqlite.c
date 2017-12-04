
#include "sniffer.h"
#include <sqlite3.h>

static int found = 0;
static FILE *fp = NULL;
static sqlite3 *db = NULL;
static struct sockaddr_in source, dest;
static char dmac[20], smac[20], ethtype[10], sip[20], dip[20];


static int callback(void *unused, int argc, char *argv[], char **col)
{
#if 0
	int i;

	for(i = 0; i < argc; i++)
		printf("%s = %s\n", col[i], argv[i] ? argv[i] : "NULL");
	printf("\n");
#else
	if (argc > 0)
		found = 1;
	else
		found = 0;
#endif

	return 0;
}

static int db_creat(char *table)
{
	int rc;
	char sql[512], *err;

	snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS %s("
		 "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
		 "DIRECTION      TEXT    NOT NULL,"   /* RX/TX */
		 "PORT           INT     NOT NULL,"   /* Switch port# */
		 "VLAN           INT     NOT NULL,"   /* VLAN ID */
		 "TAGGED         INT     NOT NULL,"   /* BOOLEAN */
		 "PRIORITY       INT     NOT NULL,"
		 "DMAC           TEXT    NOT NULL,"
		 "SMAC           TEXT    NOT NULL,"
		 "TYPE           TEXT    NOT NULL,"   /* EthType */
		 "PROTO          INT     NOT NULL,"   /* IP Prototcol */
		 "SIP            TEXT    NOT NULL,"   /* Source IP, if IPv4 */
		 "DIP            TEXT    NOT NULL,"   /* Dest. IP, if IPv4 */
		 "SPORT          INT     NOT NULL,"   /* Source port, for TCP/UDP */
		 "DPORT          INT     NOT NULL);", /* Dest. port, for TCP/UDP */
		 table);
//		"COUNT          INT     NOT NULL);";
	rc = sqlite3_exec(db, sql, callback, 0, &err);
	if (rc != SQLITE_OK) {
		errx(1, "Failed creating db table %s: %s", table, err);
		sqlite3_free(err);
		return 1;
	}

	return 0;
}

int db_open(char *fn)
{
	int rc;
	char *path;

	path = get_path(fn, ".db");
	rc = sqlite3_open(path, &db);
	if (rc) {
		fprintf(stderr, "Failed opening db, %s: %s\n", path, sqlite3_errmsg(db));
		db = NULL;

		fp = fopen(get_path(fn, ".txt"), "w");
		if (!fp)
			return 1;
	}

	db_creat(DB_GOOD);
	db_creat(DB_BAD);

	DBG("db %s open, tables created successfully", path);

	return 0;
}

static void prepare(struct snif *snif)
{
	found = 0;

	snprintf(dmac, sizeof(dmac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		 snif->dmac[0], snif->dmac[1], snif->dmac[2],
		 snif->dmac[3], snif->dmac[4], snif->dmac[5]);
	snprintf(smac, sizeof(smac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		 snif->smac[0], snif->smac[1], snif->smac[2],
		 snif->smac[3], snif->smac[4], snif->smac[5]);
	snprintf(ethtype, sizeof(ethtype), "0x%.4X", snif->ethtype);
	snprintf(sip, sizeof(sip), "%15s", inet_ntoa(snif->sip));
	snprintf(dip, sizeof(dip), "%15s", inet_ntoa(snif->sip));
}

int db_close(void)
{
	if (db)
		sqlite3_close(db);
	if (fp)
		fclose(fp);
}

int db_find(char *table, struct snif *snif)
{
	int rc;
	char sql[512];
	char *err;

	prepare(snif);

	snprintf(sql, sizeof(sql), "SELECT * FROM %s WHERE "
		 "DIRECTION = '%s' and PORT = %d and VLAN = %d and "
		 "TAGGED = '%c' and PRIORITY = %d and DMAC = '%s' and "
		 "SMAC = '%s' and TYPE = '%s' and PROTO = %d and "
		 "SIP = '%s' and DIP = '%s' and SPORT = %d and DPORT = %d;",
		 table,
		 snif->dir ? "RX" : "TX", snif->port, snif->vid,
		 snif->tagged ? 'T' : 'U', snif->prio, dmac,
		 smac, ethtype, snif->proto,
		 sip, dip, snif->sport, snif->dport);

	rc = sqlite3_exec(db, sql, callback, 0, &err);
	if (rc != SQLITE_OK || !found) {
		sqlite3_free(err);
		return 0;
	}

	return 1;
}

void db_insert(char *table, struct snif *snif)
{
	int rc;
	char sql[512];
	char *err;

	prepare(snif);
	if (!db) {
		warnx("db not open.");
		if (!fp) {
			warnx("log file not open.");
			return;
		}

		fprintf(fp, "[ PORT: %d%c | VID: %d | PRIO: %d | ",
			(int)snif->port, snif->tagged ? 'T' : 'U', (int)snif->vid,
			(int)snif->prio);
		fprintf(fp, " %s | ", snif->dir ? "RX" : "TX");
		fprintf(fp, "DMAC: %s | ", dmac);
		fprintf(fp, "SMAC: %s | ", smac);
		fprintf(fp, "TYPE: %s | ", ethtype);
//		fprintf(fp, "IPv%d | ", (unsigned int)iph->version);
		fprintf(fp, "SIP: %s |", sip);
		fprintf(fp, "DIP: %s ]\n", dip);
		fflush(fp);
		return;
	}

	snprintf(sql, sizeof(sql), "INSERT INTO %s "
		 "(DIRECTION, PORT, VLAN, TAGGED, PRIORITY, DMAC, SMAC, TYPE, PROTO, SIP, DIP, SPORT, DPORT) "
		 "VALUES ('%s', %d, %d, '%c', %d, '%s', '%s', '%s', %d, '%s', '%s', %d, %d);", table,
		 snif->dir ? "RX" : "TX",
		 snif->port, snif->vid, snif->tagged ? 'T' : 'U', snif->prio,
		 dmac, smac, ethtype, snif->proto, sip, dip, snif->sport, snif->dport);

	rc = sqlite3_exec(db, sql, callback, 0, &err);
	if (rc != SQLITE_OK) {
		if (rc != SQLITE_BUSY && rc != SQLITE_LOCKED)
			fprintf(stderr, "SQL error: %s\n", err);
		sqlite3_free(err);
		return;
	}
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
