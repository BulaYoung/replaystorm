/*
 * Thin C layer between replaystorm and DPDK. Most of the DPDK fast path (rte_eth_tx_burst,
 * rte_pktmbuf_alloc_bulk, rte_pktmbuf_mtod) consists of static inline functions that Rust
 * cannot call directly, so they are wrapped here. Built only with the "dpdk" cargo feature.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

/* One mbuf pool per TX queue: a queue is used by one sender thread only, which allocates
 * the mbufs and (inside tx_burst) gets the completed ones back. */
static struct rte_mempool *pools[RTE_MAX_QUEUES_PER_PORT];

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
int rs_dpdk_setup(uint16_t port, uint16_t ntxq, uint16_t nb_desc, unsigned nmbufs, unsigned data_room,
                  uint16_t mtu, char *err, size_t errlen)
{
	struct rte_eth_conf conf;
	memset(&conf, 0, sizeof(conf));
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
