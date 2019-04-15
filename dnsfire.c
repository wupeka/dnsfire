#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "siphash24.h"
#include "tht.h"
#include "dnsfire.h"

bool
process_packet(char*pkt,
	       size_t len,
	       entry_t **entriesp,
	       int*entries_cntp,
	       uint8_t*key)
{
	if (len < 16) {
		DPRINTF("Invalid packet - too short\n");
		return(false);
	}
	if (memcmp(pkt, "DFE1", 4)) {
		DPRINTF("Invalid packet - wrong signature\n");
		return(false);
	}
	unsigned char hash[8];
	siphash24(hash, (unsigned char*) pkt, len - 8, key);
	if (memcmp(pkt + len - 8, hash, 8)) {
		DPRINTF("Invalid packet - wrong hash\n");
		return(false);
	}
	int offset = 8;
	uint16_t in_cnt = ntohs(*(uint16_t*)(pkt + offset));
	offset += sizeof(uint16_t);
	uint16_t in6_cnt = ntohs(*(uint16_t*)(pkt + offset));
	offset += sizeof(uint16_t);
	if (len != 4 + 4 + 2 + 2 + (in_cnt * 8) + (in6_cnt * 20) + 8) {
		DPRINTF("Invalid packet - too short\n");
		return(false);
	}
	entry_t*entries = malloc((in_cnt + in6_cnt) * sizeof(entry_t));

	for (int i = 0; i < in_cnt; i++) {
		entries[i].type = AF_INET;
		entries[i].ttl = ntohl(*(uint32_t*)(pkt + offset));
		offset += sizeof(uint32_t);
		memcpy(&entries[i].addr.in,
		       pkt + offset,
		       sizeof(struct in_addr));
		offset += sizeof(struct in_addr);
	}

	for (int i = in_cnt; i < in_cnt + in6_cnt; i++) {
		entries[i].type = AF_INET6;
		entries[i].ttl = ntohl(*(uint32_t*)(pkt + offset));
		offset += sizeof(uint32_t);
		memcpy(&entries[i].addr.in6, pkt + offset,
		       sizeof(struct in6_addr));
		offset += sizeof(struct in6_addr);
	}

	*entriesp = entries;
	*entries_cntp = in_cnt + in6_cnt;
	return(true);
}

bool
hex2bin(const char *src, uint8_t *dst) {
	int rv = 0;
	for (int i = 0; i < 2; i++) {
		rv <<= 4;
		if (src[i] >= '0' && src[i] <= '9') {
			rv += src[i] - '0';
		} else if (src[i] >= 'A' && src[i] <= 'F') {
			rv += src[i] + 10 - 'A';
		} else if (src[i] >= 'a' && src[i] <= 'f') {
			rv += src[i] + 10 - 'a';
		} else {
			return(false);
		}
	}
	dst[0] = rv;
	return(true);
}
