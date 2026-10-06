#include "pcap.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAGIC_US 0xa1b2c3d4u
#define MAGIC_NS 0xa1b23c4du
#define MAGIC_PCAPNG 0x0a0d0d0au

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

const char *pcap_linktype_name(uint32_t lt)
{
	switch (lt) {
	case LINKTYPE_ETHERNET: return "Ethernet";
	case LINKTYPE_RAW:
	case LINKTYPE_RAW_OLD: return "RAW IP";
	case LINKTYPE_IPV4: return "RAW IPv4";
	case LINKTYPE_IPV6: return "RAW IPv6";
	default: return "unknown";
	}
}

int pcap_parse_header(pcap_file_t *pf, char *err, size_t errlen)
{
	if (pf->size < 4) {
		set_err(err, errlen, "file too short for pcap (%zu bytes)", pf->size);
		return -1;
	}
	uint32_t magic;
	memcpy(&magic, pf->base, 4);
	if (magic == MAGIC_PCAPNG) {
		set_err(err, errlen,
		        "this is pcapng, only classic pcap is supported. "
		        "Convert it: editcap -F pcap in.pcapng out.pcap "
		        "(for nanosecond timestamps: editcap -F nsecpcap ...)");
		return -1;
	}
	if (magic == MAGIC_US || magic == MAGIC_NS) {
		pf->swapped = 0;
	} else if (magic == __builtin_bswap32(MAGIC_US) || magic == __builtin_bswap32(MAGIC_NS)) {
		pf->swapped = 1;
		magic = __builtin_bswap32(magic);
	} else {
		set_err(err, errlen, "unknown file magic 0x%08x: not a pcap", magic);
		return -1;
	}
	pf->nsec = (magic == MAGIC_NS);
	if (pf->size < PCAP_FILE_HDR_LEN) {
		set_err(err, errlen, "file truncated: incomplete pcap header");
		return -1;
	}
	pf->snaplen = pcap_u32(pf, pf->base + 16);
	/* The upper bits of the linktype field may carry the FCS length. */
	pf->linktype = pcap_u32(pf, pf->base + 20) & 0x0FFFFFFFu;
	switch (pf->linktype) {
	case LINKTYPE_ETHERNET: pf->raw_ip = 0; break;
	case LINKTYPE_RAW:
	case LINKTYPE_RAW_OLD: pf->raw_ip = 1; break;
	case LINKTYPE_IPV4: pf->raw_ip = 4; break;
	case LINKTYPE_IPV6: pf->raw_ip = 6; break;
	default:
		set_err(err, errlen,
		        "linktype %u is not supported (need Ethernet=1 or RAW IP=101/228/229)",
		        pf->linktype);
		return -1;
	}
	return 0;
}

int pcap_open(pcap_file_t *pf, const char *path, int preload, char *err, size_t errlen)
{
	memset(pf, 0, sizeof(*pf));
	pf->fd = open(path, O_RDONLY | O_CLOEXEC);
	if (pf->fd < 0) {
		set_err(err, errlen, "cannot open %s: %s", path, strerror(errno));
		return -1;
	}
	struct stat st;
	if (fstat(pf->fd, &st) < 0 || !S_ISREG(st.st_mode)) {
		set_err(err, errlen, "%s: not a regular file", path);
		close(pf->fd);
		return -1;
	}
	pf->size = (size_t)st.st_size;
	if (pf->size == 0) {
		set_err(err, errlen, "%s: empty file", path);
		close(pf->fd);
		return -1;
	}
	int flags = MAP_PRIVATE | (preload ? MAP_POPULATE : 0);
	void *p = mmap(NULL, pf->size, PROT_READ, flags, pf->fd, 0);
	if (p == MAP_FAILED) {
		set_err(err, errlen, "mmap %s: %s", path, strerror(errno));
		close(pf->fd);
		return -1;
	}
	pf->base = p;
	pf->preloaded = preload;
	/* Indexing reads the file sequentially. */
	madvise(p, pf->size, preload ? MADV_WILLNEED : MADV_SEQUENTIAL);
	if (pcap_parse_header(pf, err, errlen) < 0) {
		pcap_close(pf);
		return -1;
	}
	return 0;
}

void pcap_close(pcap_file_t *pf)
{
	if (pf->base)
		munmap((void *)pf->base, pf->size);
	if (pf->fd > 0)
		close(pf->fd);
	pf->base = NULL;
	pf->fd = -1;
}
