#include <arpa/inet.h>
#include <hiredis/hiredis.h>

#include "sniffer.h"

/* static FILE *fp = NULL; */
/* static sqlite3 *db = NULL; */
/* static struct sockaddr_in source, dest; */

redisContext *c;

static int callback(void *unused, int argc, char *argv[], char **col)
{
	int i;

	for(i = 0; i < argc; i++)
		printf("%s = %s\n", col[i], argv[i] ? argv[i] : "NULL");
	printf("\n");

	return 0;
}

int db_open(char *fn)
{
	struct timeval timeout = { 1 };
	const char *hostname = "127.0.0.1";
	int port = 6379;
	redisReply *reply;

	c = redisConnectWithTimeout(hostname, port, timeout);
	if (c == NULL || c->err) {
		if (c) {
			printf("Connection error: %s\n", c->errstr);
			redisFree(c);
		} else {
			printf("Connection error: can't allocate redis context\n");
		}
		exit(1);
	}

	/* PING server */
	reply = redisCommand(c,"PING");
	printf("PING: %s\n", reply->str);
	freeReplyObject(reply);
	return 0;
}

int db_close(void)
{
	if (c)
		redisFree(c);
}

void fprint_mac(FILE *fp, const char *mac)
{
	fprintf(fp, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

char *to_key(struct snif *snif)
{
	char *buf;
	size_t size;
	FILE *fp = open_memstream(&buf, &size);

	fprintf(fp, "%s,%d,", snif->dir ? "Rx" : "Tx", snif->port);
	fprint_mac(fp, snif->dmac);
	fputc(',', fp);
	fprint_mac(fp, snif->smac);
	fprintf(fp, ",%#4.4x,%d,%s", snif->ethtype, snif->proto,
		inet_ntoa(snif->sip));
	fprintf(fp, ",%s,%d,%d", inet_ntoa(snif->dip), snif->sport,
		snif->dport);

	fclose(fp);
	return buf;
}

void db_insert(struct snif *snif)
{
	redisReply *reply;
	char *key = to_key(snif);

	reply = redisCommand(c,"HINCRBY good %s 1", key);
	freeReplyObject(reply);
	free(key);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
