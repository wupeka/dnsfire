#pragma once

int siphash24( unsigned char *out,
	       const unsigned char *in,
	       unsigned long long inlen,
	       const unsigned char *k );
