/*
 * On-disk cache of the option-independent part of the packet index (see index.h).
 * Building the index of a 500 GB pcap means reading the whole file; with the cache a
 * restart only maps ~21 bytes per packet.
 *
 * The cache is valid only for the same pcap: same size, mtime, inode and a hash of its
 * first and last 64 KB, and the same cache format version.
 */
#ifndef AFR_IDXCACHE_H
#define AFR_IDXCACHE_H

#include "index.h"
#include "pcap.h"

/*
 * Load the index from the cache. Returns 1 if loaded, 0 if the cache is missing or not
 * valid for this pcap (why explains it), -1 on a hard error (err).
 */
int afr_idxcache_load(const char *path, const pcap_file_t *pf, pkt_index_t *ix, char *why,
                      size_t whylen);
/* Save the index built by afr_index_build (before timestamps are normalized). */
int afr_idxcache_save(const char *path, const pcap_file_t *pf, const pkt_index_t *ix, char *err,
                      size_t errlen);

#endif
