#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "tht.h"
#include "dnsfire.h"

void
setup_entries(const char*table4,
	      const char*table6,
	      entry_t *entries,
	      int count,
	      tht_t *tht,
	      int now,
	      int ttl_ext,
	      int ttl_cap) {
	for (int i = 0; i < count; i++) {
		const char*table =
			(entries[i].type == AF_INET) ? table4 : table6;
		if (table == NULL) {
			continue;
		}

		int ttl = entries[i].ttl + ttl_ext;
		ttl = (ttl > ttl_cap) ? ttl_cap : ttl;
		char addr[INET6_ADDRSTRLEN];
		inet_ntop(entries[i].type,
			  &entries[i].addr,
			  addr,
			  INET6_ADDRSTRLEN);

		tht_entry_t *hte = tht_get(tht, &entries[i], now);
		if (hte && (hte->expiry + ttl_ext / 2) > ttl + now) {
			DPRINTF("Not re-adding entry for %s\n", addr);
			continue;
		}

		char cmdline[1024];
		snprintf(cmdline,
			 1024,
			 "ipset add -! %s %s timeout %d",
			 table,
			 addr,
			 ttl);
		DPRINTF("Adding entry for %s using \"%s\"\n", addr, cmdline);
		system(cmdline);
		if (hte) {
			hte->expiry = ttl + now;
		} else {
			tht_add(tht, &entries[i], now);
		}
	}
}

void
print_usage(char *n, char *m) {
	printf(
		"Usage: %s [-4 set4] [-6 set6] [-k key] [-b bind_address] [-p listen_port] [-e ttl_extension] [-c ttl_cap] [-h hashtable_bits]\n%s\n",
		n,
		m);
	exit(1);
}

int
main(int argc, char **argv) {
	int c;
	char *table4 = NULL, *table6 = NULL;
	char *bindaddr = "0.0.0.0";
	uint8_t key[16] = {0};
	int port = 15353;
	int ttl_ext = 600;
	int ttl_cap = 86400;
	int ht_size = 16;

	int sockfd;
	socklen_t clen;
	struct sockaddr_in saddr, caddr;
	int yes = 1;
	int n;

	tht_t *tht;



	while ((c = getopt(argc, argv, "4:6:k:b:p:e:c:h:")) != -1) {
		switch (c) {
		case '4':
			table4 = strdup(optarg);
			break;
		case '6':
			table6 = strdup(optarg);
			break;
		case 'k':
			if (strlen(optarg) != 32) {
				print_usage(argv[0],
					    "Key must be a 128-bit hex value (1)");
			}
			for (int i = 0; i < 16; i++) {
				if (!hex2bin(&optarg[2 * i], &key[i])) {
					print_usage(argv[0],
						    "Key must be a 128-bit hex value (2)");
				}
			}
			break;
		case 'b':
			bindaddr = strdup(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			if (port == 0) {
				print_usage(argv[0], "Invalid port");
			}
			break;
		case 'e':
			ttl_ext = atoi(optarg);
			if (ttl_ext == 0) {
				print_usage(argv[0], "Invalid ttl ext value");
			}
			break;
		case 'c':
			ttl_cap = atoi(optarg);
			if (ttl_cap == 0) {
				print_usage(argv[0], "Invalid ttl cap value");
			}
			break;
		case 'h':
			ht_size = atoi(optarg);
			break;
		case '?':
		default:
			print_usage(argv[0], "");
		}
	}

	tht = tht_init(ht_size, NULL, NULL);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		printf("Error opening socket\n");
		exit(1);
	}

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
		   (const void *)&yes, sizeof(int));

	bzero((char *)&saddr, sizeof(saddr));

	if (inet_pton(AF_INET, bindaddr, &saddr.sin_addr) == 1) {
		saddr.sin_family = AF_INET;
	} else if (inet_pton(AF_INET, bindaddr, &saddr.sin_addr) == 1) {
		saddr.sin_family = AF_INET6;
	} else {
		print_usage(argv[0], "Invalid bind ip");
	}
	saddr.sin_port = htons(port);

	if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		printf("Error binding\n");
		exit(1);
	}

	clen = sizeof(caddr);
	while (1) {
		char buf[65535];
		n = recvfrom(sockfd, buf, 65535, 0,
			     (struct sockaddr *)&caddr, &clen);
		if (n < 0) {
			printf("Error in recvfrom\n");
			exit(1);
		}
		entry_t *entries;
		int cnt;
		if (process_packet(buf, n, &entries, &cnt, key)) {
			int now = time(NULL);
			setup_entries(table4,
				      table6,
				      entries,
				      cnt,
				      tht,
				      now,
				      ttl_ext,
				      ttl_cap);
			tht_gc(tht, 1, now);
		}
	}
}
