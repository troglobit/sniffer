
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
	DBG("db %s open, table %s created successfully", path, DBTABLE);

	return 0;
}

int db_close(void)
{
	if (db)
		sqlite3_close(db);
	if (fp)
		fclose(fp);
}

void db_insert(struct snif *snif)
{
	int rc;
	char sql[256];
	char *err;
	char dmac[20], smac[20], ethtype[10], sip[20], dip[20];

	snprintf(dmac, sizeof(dmac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		 snif->dmac[0], snif->dmac[1], snif->dmac[2],
		 snif->dmac[3], snif->dmac[4], snif->dmac[5]);
	snprintf(smac, sizeof(smac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		 snif->smac[0], snif->smac[1], snif->smac[2],
		 snif->smac[3], snif->smac[4], snif->smac[5]);
	snprintf(ethtype, sizeof(ethtype), "0x%.4X", snif->ethtype);
	snprintf(sip, sizeof(sip), "%15s", inet_ntoa(snif->sip));
	snprintf(dip, sizeof(dip), "%15s", inet_ntoa(snif->sip));

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

	snprintf(sql, sizeof(sql), "INSERT INTO " DBTABLE "(DMAC, SMAC, TYPE, SIP, DIP) "
		 "VALUES ('%s', '%s', '%s', '%s', '%s');", dmac, smac, ethtype, sip, dip);

	rc = sqlite3_exec(db, sql, callback, 0, &err);
	if (rc != SQLITE_OK) {
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
