/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_byteorder.h>

#define GDEBUG

#define MAX_PORTS 1
#define MAX_LCORE 1

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 512

#define NUM_MBUFS	8191	/* Number of rte_mbufs in the MEM_POOL */
#define MAX_PKT_BURST	32

/* My macros */
#ifdef ETHER_MAX_LEN
#undef ETHER_MAX_LEN
#endif
#define ETHER_MAX_LEN	1514	/* 1500 + 14 */
#define IP_MAX_LEN	1500
#define UDP_MAX_LEN	1480	/* 1500 - 20 */
#define DATA_MAX_LEN	1472	/* 65536 - 20 - 8 */
#define DATA_LEN	1024
#define SRC_IP		IPv4(192,168,1,1)
#define DST_IP		IPv4(192,168,1,2)
#define DST_UDP_PORT	2333
#define SRC_UDP_PORT	2333
#define SEND_PORTID	0
#define RECV_PORTID	0
#define MBUF_BUF_SIZE	((RTE_PKTMBUF_HEADROOM) + (IP_MAX_LEN))
#define ARP_TRIES	3

static struct ether_addr src_macaddr;
static struct ether_addr dst_macaddr;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

static uint16_t	global_ippkg_id = 0;
static uint8_t	global_role = 0;	/* 0 for sender, 1 for reciver */
static char	pathname[1024];

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
};

struct lcore_queue_conf {
	struct mbuf_table tx_mbufs;
	struct rte_mempool *mbuf_pool;
};
static struct lcore_queue_conf	lcore_queue_confs[MAX_LCORE];

struct pkt_info {
	uint16_t ippkg_id;
	uint32_t src_ip;
	uint16_t src_udp_port;
	uint32_t dst_ip;
	uint16_t dst_udp_port;
	uint32_t data_len;
};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

static inline struct rte_mbuf *
udpwrapper(struct rte_mbuf *mbuf, uint16_t dst_udpport)
{
	struct udp_hdr hdr;
	char *pkt;

	memset(&hdr, 0, sizeof(hdr));
	hdr.src_port = rte_cpu_to_be_16(SRC_UDP_PORT);
	hdr.dst_port = rte_cpu_to_be_16(dst_udpport);
	hdr.dgram_len = mbuf->pkt_len + sizeof(hdr);	/* sizeof(hdr) == 8 */
	assert(hdr.dgram_len <= UDP_MAX_LEN);
	hdr.dgram_len = rte_cpu_to_be_16(hdr.dgram_len);

	/* Pre-add UDP header */
	pkt = rte_pktmbuf_prepend(mbuf, sizeof(hdr));
	rte_memcpy(pkt, &hdr, sizeof(hdr));

	return mbuf;
}

static inline struct rte_mbuf *
ipwrapper(struct rte_mbuf *mbuf, uint32_t dstip)
{
	struct ipv4_hdr hdr;
	char *pkt;

	memset(&hdr, 0, sizeof(hdr));
	hdr.version_ihl = 0x45;		/* IPv4 & 20Bytes */
	hdr.total_length = mbuf->pkt_len + sizeof(hdr);
	assert(hdr.total_length <= IP_MAX_LEN);
	hdr.packet_id = global_ippkg_id++;
	hdr.time_to_live = 64;
	hdr.next_proto_id = 0x11;	/* Code for UDP */
	hdr.src_addr = SRC_IP;
	hdr.dst_addr = dstip;

	/* CPU to big endian */
	hdr.total_length = rte_cpu_to_be_16(hdr.total_length);
	hdr.packet_id = rte_cpu_to_be_16(hdr.packet_id);
	hdr.src_addr = rte_cpu_to_be_32(hdr.src_addr);
	hdr.dst_addr = rte_cpu_to_be_32(hdr.dst_addr);
	hdr.hdr_checksum = rte_ipv4_cksum(&hdr);

	pkt = rte_pktmbuf_prepend(mbuf, sizeof(hdr));
	rte_memcpy(pkt, &hdr, sizeof(hdr));

	return mbuf;
}

static inline struct rte_mbuf *
etherwrapper(struct rte_mbuf *mbuf)
{
	struct ether_hdr hdr;
	char *pkt;

	/* Ethernet frame without CRC */
	hdr.ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	rte_memcpy(&(hdr.s_addr), &src_macaddr, sizeof(struct ether_addr));
	rte_memcpy(&(hdr.d_addr), &dst_macaddr, sizeof(struct ether_addr));
	assert(mbuf->pkt_len + sizeof(hdr) <= ETHER_MAX_LEN);

	pkt = rte_pktmbuf_prepend(mbuf, sizeof(hdr));
	rte_memcpy(pkt, &hdr, sizeof(hdr));

	return mbuf;
}

static void
send_burst(struct lcore_queue_conf *qconf, uint8_t portid)
{
	uint16_t nr_tx, nr_tx_sum = 0;

	while (qconf->tx_mbufs.len) {
		nr_tx = rte_eth_tx_burst(portid, 0,
				qconf->tx_mbufs.mbufs + nr_tx_sum,
				qconf->tx_mbufs.len);
		qconf->tx_mbufs.len -= nr_tx;
		nr_tx_sum += nr_tx;
	}

#ifdef GDEBUG
	printf("total %u packets sent: %u packets sent in this round\n",
			global_ippkg_id, nr_tx_sum);
#endif
}

static int
macaddr_get_via_arp(uint32_t ipaddr, struct lcore_queue_conf *qconf,
		struct ether_addr *macaddr)
{
	struct ether_hdr etherhdr;
	struct arp_hdr arphdr;
	struct rte_mbuf *mbuf, *bufs[MAX_PKT_BURST];
	void *pkt;
	uint16_t nb_rx;
	int round, i, buf, ret;

	mbuf = rte_pktmbuf_alloc(qconf->mbuf_pool);
	assert(mbuf != NULL);

	memset(&etherhdr, 0, sizeof(etherhdr));
	/* Set source MAC: current NIC's MAC */
	rte_memcpy(&(etherhdr.s_addr), &(src_macaddr),
			sizeof(struct ether_hdr));
	/* Set destination MAC: 0xFF FF FF FF FF FF */
	memset(&(etherhdr.d_addr), 0xFF, sizeof(etherhdr.d_addr));
	etherhdr.ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);
	/* Copy ethernet header into mbuf */
	pkt = rte_pktmbuf_append(mbuf, sizeof(etherhdr));
	rte_memcpy(pkt, &etherhdr, sizeof(etherhdr));

	/* Prepare ARP request package */
	memset(&arphdr, 0, sizeof(arphdr));
	arphdr.arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
	arphdr.arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	arphdr.arp_hln = 0x06;
	arphdr.arp_pln = 0x04;
	arphdr.arp_op = rte_cpu_to_be_16(ARP_OP_REQUEST);

	rte_memcpy(&(arphdr.arp_data.arp_sha), &(src_macaddr),
			sizeof(struct ether_hdr));
	arphdr.arp_data.arp_sip = rte_cpu_to_be_32(SRC_IP);
	arphdr.arp_data.arp_tip = rte_cpu_to_be_32(ipaddr);
	/* Copy ARP hedaer into mbuf */
	pkt = rte_pktmbuf_append(mbuf, sizeof(arphdr));
	rte_memcpy(pkt, &arphdr, sizeof(arphdr));


	/* Wait for the ARP reply */
	ret = -1;
	for (round = 0; round < ARP_TRIES; ++round) {
		/* Move mbuf into tx queue and send it */
		qconf->tx_mbufs.mbufs[0] = mbuf;
		qconf->tx_mbufs.len = 1;
		send_burst(qconf, SEND_PORTID);
		/* Poll NIC buffer to fetch expected ARP reply*/
		for (i = 0; i < 300000000; ++i) {
			nb_rx = rte_eth_rx_burst(RECV_PORTID, 0, bufs,
					MAX_PKT_BURST);
			for (buf = 0; buf < nb_rx; ++buf) {
				pkt = rte_pktmbuf_mtod(bufs[buf], void *);
				/* Check if it's a to-here ethernet frame */
				if (!(is_same_ether_addr(
					&(((struct ether_hdr *) pkt)->d_addr),
					&src_macaddr)))
					continue;
				/* Check if it's a ARP reletad ethernet frame */
				if (((struct ether_hdr *) pkt)->ether_type !=
					rte_cpu_to_be_16(ETHER_TYPE_ARP))
					continue;
				pkt = rte_pktmbuf_mtod_offset(bufs[buf], void *,
						sizeof(struct ether_hdr));
				rte_memcpy(macaddr,
					&(((struct arp_hdr *) pkt)->arp_data.arp_sha),
					sizeof(*macaddr));
				ret = 0;
				goto out;
			}
		}

	}

out:
	return ret;
}

static void
udpsender(void)
{
	struct stat sb;
	char *addr, *pkt;
	struct rte_mbuf *mbuf;
	struct lcore_queue_conf *qconf;
	struct rte_mempool *mbuf_pool;
	uint32_t nr_32k, nr_1k, blki, pkti;
	struct ether_addr macaddr;
	off_t offset;
	int ret;

	printf("\nCore %u sending packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	qconf = &lcore_queue_confs[0];
	mbuf_pool = qconf->mbuf_pool;

	/* Init src./dst. mac addrs */
	rte_eth_macaddr_get(SEND_PORTID, &macaddr);
	ether_addr_copy(&macaddr, &src_macaddr);

	ret = macaddr_get_via_arp(DST_IP, qconf, &macaddr);
	if (ret == -1) {
		printf("\nWARNING: Failed to get mac address with ARP, "
			"use boardcast instead.\n\n");
		memset(&dst_macaddr, 0xFF, sizeof(dst_macaddr));
	} else
		ether_addr_copy(&macaddr, &dst_macaddr);

	printf("Target MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
		dst_macaddr.addr_bytes[0], dst_macaddr.addr_bytes[1],
		dst_macaddr.addr_bytes[2], dst_macaddr.addr_bytes[3],
		dst_macaddr.addr_bytes[4], dst_macaddr.addr_bytes[5]);

	/* Send data in file `pathname` with UDP */
	int fd = open(pathname, O_RDONLY);
	assert(fd != -1);
	assert(fstat(fd, &sb) == 0);

	/*nr_32k = sb.st_size >> 15;
	nr_1k = (sb.st_size >> 10) & 0x1F;*/

	nr_1k = (sb.st_size >> 10);

	addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	assert(addr != MAP_FAILED);

	/* Send the file with UDP */
	offset = 0;
	/* Send packet 32KB by 32KB */
	/*for (blki = 0; blki < nr_32k; ++blki) {
		ret = rte_pktmbuf_alloc_bulk(mbuf_pool,
				qconf->tx_mbufs.mbufs, MAX_PKT_BURST);
		assert(ret == 0);

		for (pkti = 0; pkti < MAX_PKT_BURST; ++pkti) {
			mbuf = qconf->tx_mbufs.mbufs[pkti];
			[> Copy user data into mbuf <]
			pkt = rte_pktmbuf_append(mbuf, DATA_LEN);
			rte_memcpy(pkt, addr + offset, DATA_LEN);
			[> Prepend UDP/IP/Ethernet header <]
			mbuf = udpwrapper(mbuf, DST_UDP_PORT);
			mbuf = ipwrapper(mbuf, DST_IP);
			mbuf = etherwrapper(mbuf);
			offset += DATA_LEN;
		}

		qconf->tx_mbufs.len = MAX_PKT_BURST;
		send_burst(qconf, SEND_PORTID);
	}*/

	/* Send packet 1KB by 1KB */
	for (blki = 0; blki < nr_1k; ++blki) {
		mbuf = rte_pktmbuf_alloc(mbuf_pool);
		assert(mbuf != NULL);

		pkt = rte_pktmbuf_append(mbuf, DATA_LEN);
		rte_memcpy(pkt, addr + offset, DATA_LEN);
		mbuf = udpwrapper(mbuf, DST_UDP_PORT);
		mbuf = ipwrapper(mbuf, DST_IP);
		mbuf = etherwrapper(mbuf);

		qconf->tx_mbufs.mbufs[0] = mbuf;
		qconf->tx_mbufs.len = 1;
		send_burst(qconf, SEND_PORTID);
		offset += DATA_LEN;
	}

	/* Send the last piece of data that is less than 1KB */
	if (sb.st_size > offset) {
		assert((sb.st_size - offset) < DATA_LEN);

		mbuf = rte_pktmbuf_alloc(mbuf_pool);
		assert(mbuf != NULL);

		pkt = rte_pktmbuf_append(mbuf, sb.st_size - offset);
		rte_memcpy(pkt, addr + offset, sb.st_size - offset);
		mbuf = udpwrapper(mbuf, DST_UDP_PORT);
		mbuf = ipwrapper(mbuf, DST_IP);
		mbuf = etherwrapper(mbuf);

		qconf->tx_mbufs.mbufs[0] = mbuf;
		qconf->tx_mbufs.len = 1;
		send_burst(qconf, SEND_PORTID);
	}

	munmap(addr, sb.st_size);
	close(fd);
}

static inline void
parse_pkt_info(struct rte_mbuf *mbuf, struct pkt_info *pktinfo)
{
	void *addr;

	/* Remove ethernet header */
	addr = rte_pktmbuf_adj(mbuf, 14);
	assert(addr != NULL);

	/* Get src./dst. ip from IPv4 header and then remove it */
	pktinfo->src_ip = ((struct ipv4_hdr *) addr)->src_addr;
	pktinfo->dst_ip = ((struct ipv4_hdr *) addr)->dst_addr;
	pktinfo->ippkg_id = ((struct ipv4_hdr *) addr)->packet_id;

	/* To CPU prefered byte order */
	pktinfo->src_ip = rte_be_to_cpu_32(pktinfo->src_ip);
	pktinfo->dst_ip = rte_be_to_cpu_32(pktinfo->dst_ip);
	pktinfo->ippkg_id = rte_be_to_cpu_16(pktinfo->ippkg_id);

	addr = rte_pktmbuf_adj(mbuf, 20);
	assert(addr != NULL);

	/* Get src./dst. port and data len from UDP header and
	 * then remove it */
	pktinfo->src_udp_port = ((struct udp_hdr *) addr)->src_port;
	pktinfo->dst_udp_port = ((struct udp_hdr *) addr)->dst_port;
	pktinfo->data_len = ((struct udp_hdr *) addr)->dgram_len;

	/* To CPU prefered byte order */
	pktinfo->src_udp_port = rte_be_to_cpu_16(pktinfo->src_udp_port);
	pktinfo->dst_udp_port = rte_be_to_cpu_16(pktinfo->dst_udp_port);
	pktinfo->data_len = rte_be_to_cpu_16(pktinfo->data_len) - 8;

	addr = rte_pktmbuf_adj(mbuf, 8);
	assert(addr != NULL);
}

static void
udpreciver(void)
{
	struct rte_mbuf *bufs[MAX_PKT_BURST];
	struct pkt_info pktinfo;
	uint16_t nb_rx;
	int buf;
	ssize_t n;

	printf("\nCore %u recving packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	int fd = open(pathname, O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRWXG);
	assert(fd != -1);

	for (;;) {
		/* Listen at port 0 */
		nb_rx = rte_eth_rx_burst(RECV_PORTID, 0, bufs, MAX_PKT_BURST);
		for (buf = 0; buf < nb_rx; ++buf) {
			parse_pkt_info(bufs[buf], &pktinfo);
			if (pktinfo.dst_ip != DST_IP) {
				rte_pktmbuf_free(bufs[buf]);
				continue;
			}
			n = write(fd, rte_pktmbuf_mtod(bufs[buf], void *),
					pktinfo.data_len);
			assert(n == pktinfo.data_len);
#ifdef GDEBUG
			printf("#%u (%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u): %u bytes\n",
				pktinfo.ippkg_id,
				(pktinfo.src_ip & 0xff000000) >> 24,
				(pktinfo.src_ip & 0x00ff0000) >> 16,
				(pktinfo.src_ip & 0x0000ff00) >> 8,
				(pktinfo.src_ip & 0x000000ff),
				pktinfo.src_udp_port,
				(pktinfo.dst_ip & 0xff000000) >> 24,
				(pktinfo.dst_ip & 0x00ff0000) >> 16,
				(pktinfo.dst_ip & 0x0000ff00) >> 8,
				(pktinfo.dst_ip & 0x000000ff),
				pktinfo.dst_udp_port,
				pktinfo.data_len);
#endif
			rte_pktmbuf_free(bufs[buf]);
		}
	}
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static void
lcore_main(void)
{
	(global_role == 0) ? udpreciver() : udpsender();
}

static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] --"
		" [reciver|sender]"
		" -f path-to-file",
		prgname);
}

static int
parse_args(int argc, char **argv)
{
	if (argc != 4)
		return -1;

	if (strcmp(argv[1], "reciver") == 0) {
		global_role = 0;
	} else if (strcmp(argv[1], "sender") == 0) {
		global_role = 1;
	} else
		return -1;

	if (strcmp(argv[2], "-f") == 0) {
		sprintf(pathname, "%s", argv[3]);
	} else
		return -1;

	return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	unsigned nb_ports;
	struct rte_mempool *mbuf_pool;
	int lcore;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	assert(ret >= 0);

	argc -= ret;
	argv += ret;

	if (parse_args(argc, argv) < 0) {
		print_usage(argv[0]);
		rte_exit(EXIT_FAILURE, NULL);
	}

	nb_ports = rte_eth_dev_count();
	assert(nb_ports > 0);

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
		0, 0, MBUF_BUF_SIZE, SOCKET_ID_ANY);
	assert(mbuf_pool != NULL);

	/* Share the mbuf_pool between lcores */
	for (lcore = 0; lcore < MAX_LCORE; ++lcore)
		lcore_queue_confs[lcore].mbuf_pool = mbuf_pool;

	/* Initialize the first port. */
	assert(port_init(0, mbuf_pool) == 0);

	if (rte_lcore_count() > MAX_LCORE)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
