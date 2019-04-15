#pragma once
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>
#include "dnsfire.h"

typedef struct ht_entry tht_entry_t;
typedef struct tht tht_t;
typedef void (*tht_cleancb)(void *data, tht_entry_t *entry);

struct ht_entry {
	int		type;
	uint32_t	expiry;
	union {
		struct in_addr	       in;
		struct in6_addr	       in6;
	} addr;
	tht_entry_t *      next;
};


struct tht {
	int		   sz;
	uint32_t	   mask;
	uint32_t	   iv;
	uint32_t	   gc_pos;
	tht_entry_t **	   table;
	tht_cleancb	   cleancb;
	void *		   cbdata;
};

tht_t *tht_init(int bitsize, tht_cleancb cb, void *cbdata);
void tht_clean(tht_t *tht);
void tht_gc(tht_t *tht, int step, int now);
tht_entry_t *tht_get(tht_t *tht, entry_t *entry, int now);
void tht_add(tht_t *tht, entry_t *entry, int now);
