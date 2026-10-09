/*
 * Thin C layer between replaystorm and DPDK. Most of the DPDK fast path (rte_eth_tx_burst,
 * rte_pktmbuf_alloc_bulk, rte_pktmbuf_mtod) consists of static inline functions that Rust
 * cannot call directly, so they are wrapped here. Built only with the "dpdk" cargo feature.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_memory.h>
#include <unistd.h>

/* One mbuf pool per TX queue: a queue is used by one sender thread only, which allocates
 * the mbufs and (inside tx_burst) gets the completed ones back. */
static struct rte_mempool *pools[RTE_MAX_QUEUES_PER_PORT];
/* Zero-copy: per queue, mbufs without data room that point into the preloaded file. Each
 * keeps its external buffer descriptor (shared info) in its private area. */
static struct rte_mempool *zc_pools[RTE_MAX_QUEUES_PER_PORT];

int rs_dpdk_init(int argc, char **argv)
{
	int r = rte_eal_init(argc, argv);
	return r < 0 ? -rte_errno : r;
}

const char *rs_dpdk_strerror(int e)
{
	return rte_strerror(e < 0 ? -e : e);
}

unsigned rs_dpdk_port_count(void)
{
	return rte_eth_dev_count_avail();
}

/* Port by device name (PCI address, vdev name) or by number. */
int rs_dpdk_find_port(const char *name, uint16_t *port)
{
	if (rte_eth_dev_get_port_by_name(name, port) == 0)
		return 0;
	char *end;
	unsigned long v = strtoul(name, &end, 10);
	if (*name && !*end && v < RTE_MAX_ETHPORTS && rte_eth_dev_is_valid_port((uint16_t)v)) {
		*port = (uint16_t)v;
		return 0;
	}
	return -ENODEV;
}

int rs_dpdk_port_name(uint16_t port, char *buf, size_t n)
{
	char name[RTE_ETH_NAME_MAX_LEN];
	if (rte_eth_dev_get_name_by_port(port, name) != 0)
		return -ENODEV;
	snprintf(buf, n, "%s", name);
	return 0;
}

int rs_dpdk_info(uint16_t port, uint16_t *max_txq, uint16_t *max_desc, uint16_t *mtu, int *socket, char *driver,
                 size_t n)
{
	struct rte_eth_dev_info info;
	int r = rte_eth_dev_info_get(port, &info);
	if (r != 0)
		return r;
	*max_txq = info.max_tx_queues;
	*max_desc = info.tx_desc_lim.nb_max;
	if (rte_eth_dev_get_mtu(port, mtu) != 0)
		*mtu = 1500;
	*socket = rte_eth_dev_socket_id(port);
	snprintf(driver, n, "%s", info.driver_name ? info.driver_name : "?");
	return 0;
}

int rs_dpdk_link(uint16_t port, uint32_t *speed_mbps, int *up)
{
	struct rte_eth_link l;
	memset(&l, 0, sizeof(l));
	int r = rte_eth_link_get_nowait(port, &l);
	if (r != 0)
		return r;
	*speed_mbps = (l.link_speed == RTE_ETH_SPEED_NUM_UNKNOWN) ? 0 : l.link_speed;
	*up = l.link_status == RTE_ETH_LINK_UP;
	return 0;
}

static int fail(char *err, size_t n, const char *what, int r)
{
	snprintf(err, n, "%s: %s", what, rte_strerror(r < 0 ? -r : r));
	return r < 0 ? r : -r;
}

/*
 * Configure the port with ntxq TX queues of nb_desc descriptors each and one mbuf pool
 * per queue, then start it. RX is not used; a single RX queue is set up only for drivers
 * that refuse a configuration without one.
 */
/*
 * zc: also create the zero-copy pools and, if the driver can, enable multi-segment frames
 * (a copied header followed by the rest of the frame in the file); *zc_ok tells whether it
 * can. Frames that need no header of their own go out as one segment on any driver.
 */
int rs_dpdk_setup(uint16_t port, uint16_t ntxq, uint16_t nb_desc, unsigned nmbufs, unsigned data_room,
                  uint16_t mtu, int zc, int *zc_ok, char *err, size_t errlen)
{
	struct rte_eth_conf conf;
	memset(&conf, 0, sizeof(conf));
	*zc_ok = 0;
	if (zc) {
		struct rte_eth_dev_info info;
		if (rte_eth_dev_info_get(port, &info) == 0 &&
		    (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)) {
			conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
			*zc_ok = 1;
		}
	}
	int socket = rte_eth_dev_socket_id(port);
	if (socket < 0)
		socket = 0;
	uint16_t nrx = 0;
	int r = rte_eth_dev_configure(port, 0, ntxq, &conf);
	if (r != 0) {
		nrx = 1;
		r = rte_eth_dev_configure(port, 1, ntxq, &conf);
		if (r != 0)
			return fail(err, errlen, "rte_eth_dev_configure", r);
	}
	uint16_t nb_rxd = 128;
	rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_desc);
	if (mtu)
		rte_eth_dev_set_mtu(port, mtu); /* not every driver can, the frames are filtered anyway */
	for (uint16_t q = 0; q < ntxq; q++) {
		char name[RTE_MEMPOOL_NAMESIZE];
		snprintf(name, sizeof(name), "rs_tx_%u_%u", port, q);
		struct rte_mempool *mp = rte_pktmbuf_pool_create_by_ops(
		    name, nmbufs, 0, 0, (uint16_t)(data_room + RTE_PKTMBUF_HEADROOM), socket, "ring_sp_sc");
		if (!mp)
			mp = rte_pktmbuf_pool_create(name, nmbufs, 0, 0,
			                             (uint16_t)(data_room + RTE_PKTMBUF_HEADROOM), socket);
		if (!mp)
			return fail(err, errlen, "mbuf pool", rte_errno);
		pools[q] = mp;
		if (zc) {
			snprintf(name, sizeof(name), "rs_zc_%u_%u", port, q);
			uint16_t priv = (uint16_t)RTE_ALIGN(sizeof(struct rte_mbuf_ext_shared_info), RTE_MBUF_PRIV_ALIGN);
			struct rte_mempool *zp = rte_pktmbuf_pool_create_by_ops(name, nmbufs, 0, priv, 0, socket, "ring_sp_sc");
			if (!zp)
				zp = rte_pktmbuf_pool_create(name, nmbufs, 0, priv, 0, socket);
			if (!zp)
				return fail(err, errlen, "zero-copy mbuf pool", rte_errno);
			zc_pools[q] = zp;
		}
		r = rte_eth_tx_queue_setup(port, q, nb_desc, (unsigned)socket, NULL);
		if (r != 0)
			return fail(err, errlen, "rte_eth_tx_queue_setup", r);
	}
	if (nrx) {
		struct rte_mempool *rp =
		    rte_pktmbuf_pool_create("rs_rx", 1023, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket);
		if (!rp)
			return fail(err, errlen, "RX mbuf pool", rte_errno);
		r = rte_eth_rx_queue_setup(port, 0, nb_rxd, (unsigned)socket, NULL, rp);
		if (r != 0)
			return fail(err, errlen, "rte_eth_rx_queue_setup", r);
	}
	r = rte_eth_dev_start(port);
	if (r != 0)
		return fail(err, errlen, "rte_eth_dev_start", r);
	return nb_desc;
}

/* Fast path. */

int rs_dpdk_alloc(uint16_t q, struct rte_mbuf **m, unsigned n)
{
	return rte_pktmbuf_alloc_bulk(pools[q], m, n);
}

uint8_t *rs_dpdk_data(struct rte_mbuf *m, uint32_t len)
{
	m->data_len = (uint16_t)len;
	m->pkt_len = len;
	return rte_pktmbuf_mtod(m, uint8_t *);
}

/* Zero-copy fast path. */

int rs_dpdk_alloc_zc(uint16_t q, struct rte_mbuf **m, unsigned n)
{
	return rte_pktmbuf_alloc_bulk(zc_pools[q], m, n);
}

static void zc_free_cb(void *addr, void *opaque)
{
	/* The file stays mapped for the whole run: nothing to free. */
	(void)addr;
	(void)opaque;
}

static int iova_is_va;

/* Point mbuf m at len bytes of the preloaded file at addr. */
void rs_dpdk_attach(struct rte_mbuf *m, void *addr, uint32_t len)
{
	struct rte_mbuf_ext_shared_info *sh = rte_mbuf_to_priv(m);
	sh->free_cb = zc_free_cb;
	sh->fcb_opaque = NULL;
	rte_mbuf_ext_refcnt_set(sh, 1);
	rte_iova_t iova = iova_is_va ? (rte_iova_t)(uintptr_t)addr : rte_mem_virt2iova(addr);
	rte_pktmbuf_attach_extbuf(m, addr, iova, (uint16_t)len, sh);
	m->data_off = 0;
	m->data_len = (uint16_t)len;
	m->pkt_len = len;
}

/* Frame = head (copied header) + tail (rest of the frame in the file). */
void rs_dpdk_chain(struct rte_mbuf *head, struct rte_mbuf *tail)
{
	head->next = tail;
	head->nb_segs = 2;
	head->pkt_len = head->data_len + tail->data_len;
}

/*
 * Register the preloaded file as external memory and map it for the device's DMA (for
 * mlx5: a memory region). addr and len are aligned to page_sz. Returns 0 when mapped, 1
 * when the driver needs no mapping (it copies the data itself), negative on error.
 */
int rs_dpdk_extmem(uint16_t port, void *addr, size_t len, size_t dma_len, size_t page_sz, char *err, size_t errlen)
{
	iova_is_va = rte_eal_iova_mode() == RTE_IOVA_VA;
	if (rte_extmem_register(addr, len, NULL, 0, page_sz) != 0 && rte_errno != EEXIST)
		return fail(err, errlen, "rte_extmem_register", rte_errno);
	struct rte_eth_dev_info info;
	int r = rte_eth_dev_info_get(port, &info);
	if (r != 0)
		return fail(err, errlen, "rte_eth_dev_info_get", r);
	/* Only the mapped part (the file), not the alignment after it. */
	if (rte_dev_dma_map(info.device, addr, (uint64_t)(uintptr_t)addr, dma_len) != 0) {
		if (rte_errno == ENOTSUP)
			return 1;
		return fail(err, errlen, "rte_dev_dma_map", rte_errno);
	}
	return 0;
}

void rs_dpdk_extmem_release(uint16_t port, void *addr, size_t len, size_t dma_len, int mapped)
{
	struct rte_eth_dev_info info;
	if (mapped && rte_eth_dev_info_get(port, &info) == 0)
		rte_dev_dma_unmap(info.device, addr, (uint64_t)(uintptr_t)addr, dma_len);
	rte_extmem_unregister(addr, len);
}

uint16_t rs_dpdk_tx(uint16_t port, uint16_t q, struct rte_mbuf **m, uint16_t n)
{
	return rte_eth_tx_burst(port, q, m, n);
}

/* Ask the driver to return completed mbufs to the pool (not every driver supports it). */
void rs_dpdk_tx_cleanup(uint16_t port, uint16_t q)
{
	rte_eth_tx_done_cleanup(port, q, 0);
}

void rs_dpdk_free(struct rte_mbuf **m, unsigned n)
{
	rte_pktmbuf_free_bulk(m, n);
}

int rs_dpdk_stats(uint16_t port, uint64_t *opackets, uint64_t *obytes, uint64_t *oerrors)
{
	struct rte_eth_stats s;
	int r = rte_eth_stats_get(port, &s);
	if (r != 0)
		return r;
	*opackets = s.opackets;
	*obytes = s.obytes;
	*oerrors = s.oerrors;
	return 0;
}

void rs_dpdk_close(uint16_t port)
{
	rte_eth_dev_stop(port);
	rte_eth_dev_close(port);
}

void rs_dpdk_cleanup(void)
{
	rte_eal_cleanup();
}
