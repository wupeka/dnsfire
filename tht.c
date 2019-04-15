#include <stdlib.h>
#include <string.h>

#include "tht.h"
#include "siphash24.h"
#include "lookup3.h"

tht_t *
tht_init(int bitsize, tht_cleancb cb, void *data) {
	tht_t *tht = malloc(sizeof(tht_t));
	tht->sz = 1 << bitsize;
	tht->mask = tht->sz - 1;
	tht->iv = random();
	tht->table = malloc(tht->sz * sizeof(tht_entry_t*));
	tht->gc_pos = 0;
	tht->cleancb = cb;
	tht->cbdata = data;
	memset(tht->table, 0, tht->sz * sizeof(tht_entry_t*));
	return(tht);
}

void
tht_clean(tht_t *tht) {
	for (int i = 0; i < tht->sz; i++) {
		tht_entry_t *he = tht->table[i];
		while (he != NULL) {
			if (tht->cleancb != NULL) {
				tht->cleancb(tht->cbdata, he);
			}
			tht_entry_t *e = he;
			he = e->next;
			free(e);
		}
	}
	free(tht->table);
	free(tht);
}

void
tht_gc(tht_t *tht, int step, int now) {
	for (int i = 0; i < step; i++) {
		tht_entry_t **hep = &(tht->table[tht->gc_pos]);
		while (*hep != NULL) {
			if ((*hep)->expiry < now) {
				tht_entry_t *e = *hep;
				*hep = e->next;
				if (tht->cleancb != NULL) {
					tht->cleancb(tht->cbdata, e);
				}
				free(e);
			} else {
				hep = &(*hep)->next;
			}
		}
		tht->gc_pos++;
		tht->gc_pos %= tht->sz;
	}
}

tht_entry_t *
tht_get(tht_t *tht, entry_t *entry, int now) {
	uint32_t h = hashword((uint32_t*) &entry->addr,
			      entry->type == AF_INET ? 1 : 4,
			      tht->iv);
	h &= tht->mask;
	tht_entry_t **hep = &(tht->table[h]);
	while (*hep != NULL) {
		if ((*hep)->expiry < now) {
			tht_entry_t *e = *hep;
			*hep = e->next;
			if (tht->cleancb != NULL) {
				tht->cleancb(tht->cbdata, e);
			}
			free(e);
			continue;
		}
		if (entry->type == (*hep)->type) {
			if (!memcmp(&entry->addr, &(*hep)->addr,
				    entry->type == AF_INET ? 4 : 16)) {
				return(*hep);
			}
		}
		hep = &(*hep)->next;
	}
	return(NULL);
}

void
tht_add(tht_t *tht, entry_t *entry, int now) {
	tht_entry_t *nhe = malloc(sizeof(tht_entry_t));
	nhe->type = entry->type;
	nhe->expiry = entry->ttl + now;
	memcpy(&nhe->addr, &entry->addr, sizeof(entry->addr));
	nhe->next = NULL;

	uint32_t h = hashword((uint32_t*) &entry->addr,
			      entry->type == AF_INET ? 1 : 4,
			      tht->iv);
	h &= tht->mask;
	tht_entry_t *hep = tht->table[h];
	if (hep == NULL) {
		tht->table[h] = nhe;
	} else {
		while (hep->next != NULL) {
			hep = hep->next;
		}
		hep->next = nhe;
	}
}
