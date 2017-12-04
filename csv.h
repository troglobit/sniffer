#ifndef SNIFFER_CSV_H_
#define SNIFFER_CSV_H_

#include "sniffer.h"

int  csv_open   (char *fn);
int  csv_close  (void);
void csv_insert (struct snif *snif);

#endif /* SNIFFER_CSV_H_ */
