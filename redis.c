#include <arpa/inet.h>
#include <hiredis/hiredis.h>

#include "sniffer.h"

redisContext *c;

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
	reply = redisCommand(c, "PING");
	DBG("PING: %s", reply->str);
	freeReplyObject(reply);

	return 0;
}

int db_close(void)
{
	if (c)
		redisFree(c);
}

void fprint_mac(FILE *fp, const unsigned char *mac)
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

int db_find(char *hash, struct snif *snif)
{
	redisReply *reply;
	char *key = to_key(snif);
	int exists;

	reply = redisCommand(c, "HGET %s %s 1", hash, key);
	DBG("HGET reply: %d", reply->type);
	exists = reply->type != REDIS_REPLY_NIL;
	freeReplyObject(reply);
	free(key);

	return exists;
}

void db_insert(char *hash, struct snif *snif)
{
	redisReply *reply;
	char *key = to_key(snif);

	reply = redisCommand(c, "HINCRBY %s %s 1", hash, key);
	freeReplyObject(reply);
	free(key);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
