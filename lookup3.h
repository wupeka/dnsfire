#pragma once

#include <stddef.h>
#include <stdint.h>

uint32_t hashword(const uint32_t *k, size_t length, uint32_t initval);
