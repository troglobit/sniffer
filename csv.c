#include "sniffer.h"

static FILE *fp = NULL;

int csv_open(char *fn)
{
	fp = fopen(get_path(fn, ".csv"), "w");
	if (!fp)
		return -1;

	fprintf(fp, "frameDir,framePort,frameVID,frameTagged,framePrio,frameDMAC,frameSMAC,frameEthType,frameProto,frameSIP,frameDIP,frameSPORT,frameDPORT\r\n");
	return 0;
}

int csv_close(void)
{
	int rc = 0;

	if (fp) {
		rc = fclose(fp);
		fp = NULL;
	}

	return rc;
}

/* Dir,Port,VID,Tagged,Prio,DMAC,SMAC,EthType,Proto,SIP,DIP,SPORT,DPORT */
void csv_insert(struct snif *snif)
{
	char dmac[20], smac[20], ethtype[10], sip[20], dip[20];

	snprintf(dmac, sizeof(dmac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		 snif->dmac[0], snif->dmac[1], snif->dmac[2],
		 snif->dmac[3], snif->dmac[4], snif->dmac[5]);
	snprintf(smac, sizeof(smac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		 snif->smac[0], snif->smac[1], snif->smac[2],
		 snif->smac[3], snif->smac[4], snif->smac[5]);
	snprintf(ethtype, sizeof(ethtype), "0x%.4X", snif->ethtype);
	snprintf(sip, sizeof(sip), "%s", inet_ntoa(snif->sip));
	snprintf(dip, sizeof(dip), "%s", inet_ntoa(snif->sip));

	fprintf(fp, "%s,%d,%d,%c,%d,%s,%s,0x%02d,%d,%s,%s,%d,%d\r\n",
		snif->dir ? "RX" : "TX",
		(int)snif->port,
		(int)snif->vid,
		snif->tagged ? 'T' : 'U',
		(int)snif->prio,
		dmac, smac, snif->ethtype, snif->proto,
		sip, dip, snif->sport, snif->dport);

	fflush(fp);
}


/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */

