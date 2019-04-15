#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#ifdef DEBUG
#define DPRINTF(...) fprintf(stderr, ## __VA_ARGS__)
#else /* ifdef DEBUG */
#define DPRINTF(...) {}
#endif /* ifdef DEBUG */

typedef struct entry {
	int		type;
	uint32_t	ttl;
	union {
		struct in_addr	       in;
		struct in6_addr	       in6;
	} addr;
} entry_t;

bool process_packet(char*pkt,
		    size_t len,
		    entry_t **entriesp,
		    int*entries_cntp,
		    uint8_t*key);

bool hex2bin(const char *src, uint8_t *dst);
