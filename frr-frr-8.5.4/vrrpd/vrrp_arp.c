/*
 * VRRP ARP handling.
 * Copyright (C) 2001-2017 Alexandre Cassen
 * Portions:
 *     Copyright (C) 2018-2019 Cumulus Networks, Inc.
 *     Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include <linux/if_packet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <sys/socket.h>
#include <errno.h>

#include "lib/if.h"
#include "lib/linklist.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/prefix.h"
#include "lib/thread.h"

#include "vrrp.h"
#include "vrrp_arp.h"
#include "vrrp_debug.h"

#define VRRP_LOGPFX "[ARP] "

/*
 * The size of the garp packet buffer should be the large enough to hold the
 * largest arp packet to be sent + the size of the link layer header for the
 * corresponding protocol. In this case we hardcode for Ethernet.
 */
#define GARP_BUFFER_SIZE                                                       \
	sizeof(struct ether_header) + sizeof(struct arphdr) + 2 * ETH_ALEN     \
		+ 2 * sizeof(struct in_addr)

/* static vars */
static int garp_fd = -1;

static int vrrp_lb_arp_read(struct thread *thread);

/* Send the gratuitous ARP message */
static ssize_t vrrp_send_garp(struct interface *ifp, uint8_t *buf,
			      ssize_t pack_len)
{
	struct sockaddr_ll sll;
	ssize_t len;

	/* Build the dst device */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = ETH_P_ARP;
	sll.sll_ifindex = (int)ifp->ifindex;
	sll.sll_halen = ifp->hw_addr_len;
	memset(sll.sll_addr, 0xFF, ETH_ALEN);

	/* Send packet */
	len = sendto(garp_fd, buf, pack_len, 0, (struct sockaddr *)&sll,
		     sizeof(sll));

	return len;
}

/* Build a gratuitous ARP message over a specific interface */
static ssize_t vrrp_build_garp(uint8_t *buf, struct interface *ifp,
			       struct in_addr *v4)
{
	uint8_t *arp_ptr;

	if (ifp->hw_addr_len == 0)
		return -1;

	/* Build Ethernet header */
	struct ether_header *eth = (struct ether_header *)buf;

	memset(eth->ether_dhost, 0xFF, ETH_ALEN);
	memcpy(eth->ether_shost, ifp->hw_addr, ETH_ALEN);
	eth->ether_type = htons(ETHERTYPE_ARP);

	/* Build ARP payload */
	struct arphdr *arph = (struct arphdr *)(buf + ETHER_HDR_LEN);

	arph->ar_hrd = htons(HWTYPE_ETHER);
	arph->ar_pro = htons(ETHERTYPE_IP);
	arph->ar_hln = ifp->hw_addr_len;
	arph->ar_pln = sizeof(struct in_addr);
	arph->ar_op = htons(ARPOP_REQUEST);
	arp_ptr = (uint8_t *)(arph + 1);
	/* Source MAC: us */
	memcpy(arp_ptr, ifp->hw_addr, ifp->hw_addr_len);
	arp_ptr += ifp->hw_addr_len;
	/* Source IP: us */
	memcpy(arp_ptr, v4, sizeof(struct in_addr));
	arp_ptr += sizeof(struct in_addr);
	/* Dest MAC: broadcast */
	memset(arp_ptr, 0xFF, ETH_ALEN);
	arp_ptr += ifp->hw_addr_len;
	/* Dest IP: us */
	memcpy(arp_ptr, v4, sizeof(struct in_addr));
	arp_ptr += sizeof(struct in_addr);

	return arp_ptr - buf;
}

void vrrp_garp_send(struct vrrp_router *r, struct in_addr *v4)
{
	struct interface *ifp = r->mvl_ifp;
	uint8_t garpbuf[GARP_BUFFER_SIZE];
	ssize_t garpbuf_len;
	ssize_t sent_len;
	char astr[INET_ADDRSTRLEN];

	/* If the interface doesn't support ARP, don't try sending */
	if (ifp->flags & IFF_NOARP) {
		zlog_warn(
			VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			"Unable to send gratuitous ARP on %s; has IFF_NOARP",
			r->vr->vrid, family2str(r->family), ifp->name);
		return;
	}

	/* Build garp */
	garpbuf_len = vrrp_build_garp(garpbuf, ifp, v4);

	if (garpbuf_len < 0) {
		zlog_warn(
			VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			"Unable to send gratuitous ARP on %s; MAC address unknown",
			r->vr->vrid, family2str(r->family), ifp->name);
		return;
	};

	/* Send garp */
	inet_ntop(AF_INET, v4, astr, sizeof(astr));

	DEBUGD(&vrrp_dbg_arp,
	       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
	       "Sending gratuitous ARP on %s for %s",
	       r->vr->vrid, family2str(r->family), ifp->name, astr);
	if (DEBUG_MODE_CHECK(&vrrp_dbg_arp, DEBUG_MODE_ALL))
		zlog_hexdump(garpbuf, garpbuf_len);

	sent_len = vrrp_send_garp(ifp, garpbuf, garpbuf_len);

	if (sent_len < 0)
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			  "Error sending gratuitous ARP on %s for %s",
			  r->vr->vrid, family2str(r->family), ifp->name, astr);
	else
		++r->stats.garp_tx_cnt;
}

void vrrp_garp_send_all(struct vrrp_router *r)
{
	assert(r->family == AF_INET);

	struct interface *ifp = r->mvl_ifp;

	/* If the interface doesn't support ARP, don't try sending */
	if (ifp->flags & IFF_NOARP) {
		zlog_warn(
			VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			"Unable to send gratuitous ARP on %s; has IFF_NOARP",
			r->vr->vrid, family2str(r->family), ifp->name);
		return;
	}

	struct listnode *ln;
	struct ipaddr *ip;

	for (ALL_LIST_ELEMENTS_RO(r->addrs, ln, ip))
		vrrp_garp_send(r, &ip->ipaddr_v4);
}


void vrrp_garp_init(void)
{
	/* Create the socket descriptor */
	/* FIXME: why ETH_P_RARP? */
	errno = 0;
	frr_with_privs(&vrrp_privs) {
		garp_fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
				 htons(ETH_P_RARP));
	}

	if (garp_fd > 0) {
		DEBUGD(&vrrp_dbg_sock,
		       VRRP_LOGPFX "Initialized gratuitous ARP socket");
		DEBUGD(&vrrp_dbg_arp,
		       VRRP_LOGPFX "Initialized gratuitous ARP subsystem");
	} else {
		zlog_err(VRRP_LOGPFX
			 "Error initializing gratuitous ARP subsystem");
	}
}

void vrrp_garp_fini(void)
{
	close(garp_fd);
	garp_fd = -1;

	DEBUGD(&vrrp_dbg_arp,
	       VRRP_LOGPFX "Deinitialized gratuitous ARP subsystem");
}

bool vrrp_garp_is_init(void)
{
        return garp_fd > 0;
}

static bool vrrp_lb_match_vip(struct vrrp_router *r, const struct in_addr *ip)
{
        struct listnode *ln;
        struct ipaddr *addr;

        for (ALL_LIST_ELEMENTS_RO(r->addrs, ln, addr))
                if (addr->ipa_type == IPADDR_V4
                    && addr->ipaddr_v4.s_addr == ip->s_addr)
                        return true;

        return false;
}

static void vrrp_lb_neigh_update(struct vrrp_router *r,
                                 const struct in_addr *ip,
                                 const struct ethaddr *mac)
{
        struct {
                struct nlmsghdr n;
                struct ndmsg ndm;
                char buf[64];
        } req;
        struct sockaddr_nl snl = {
                .nl_family = AF_NETLINK,
        };
        struct rtattr *rta;
        struct iovec iov;
        struct msghdr msg;
        char resp[NLMSG_LENGTH(sizeof(struct nlmsgerr))];
        struct iovec riov;
        struct msghdr rmsg;
        int fd = -1;

        if (!r->mvl_ifp || r->mvl_ifp->ifindex <= 0)
                return;

        fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0) {
                zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
                          "Unable to open netlink socket for neighbor update on %s: %s",
                          r->vr->vrid, r->mvl_ifp->name, safe_strerror(errno));
                return;
        }

        memset(&req, 0, sizeof(req));
        req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
        req.n.nlmsg_type = RTM_NEWNEIGH;
        req.n.nlmsg_flags =
                NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
        req.ndm.ndm_family = AF_INET;
        req.ndm.ndm_ifindex = r->mvl_ifp->ifindex;
        req.ndm.ndm_state = NUD_PERMANENT;

        rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
        rta->rta_type = NDA_DST;
        rta->rta_len = RTA_LENGTH(sizeof(ip->s_addr));
        memcpy(RTA_DATA(rta), &ip->s_addr, sizeof(ip->s_addr));
        req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + rta->rta_len;

        rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
        rta->rta_type = NDA_LLADDR;
        rta->rta_len = RTA_LENGTH(sizeof(mac->octet));
        memcpy(RTA_DATA(rta), mac->octet, sizeof(mac->octet));
        req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + rta->rta_len;

        memset(&msg, 0, sizeof(msg));
        iov.iov_base = &req;
        iov.iov_len = req.n.nlmsg_len;
        msg.msg_name = &snl;
        msg.msg_namelen = sizeof(snl);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        if (sendmsg(fd, &msg, 0) < 0) {
                zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
                          "Failed to program neighbor entry on %s: %s",
                          r->vr->vrid, r->mvl_ifp->name, safe_strerror(errno));
                goto out;
        }

        memset(resp, 0, sizeof(resp));
        memset(&rmsg, 0, sizeof(rmsg));
        memset(&riov, 0, sizeof(riov));
        riov.iov_base = resp;
        riov.iov_len = sizeof(resp);
        rmsg.msg_name = &snl;
        rmsg.msg_namelen = sizeof(snl);
        rmsg.msg_iov = &riov;
        rmsg.msg_iovlen = 1;

        if (recvmsg(fd, &rmsg, 0) < 0) {
                zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
                          "Failed to receive neighbor response on %s: %s",
                          r->vr->vrid, r->mvl_ifp->name, safe_strerror(errno));
                goto out;
        }

        struct nlmsghdr *h = (struct nlmsghdr *)resp;
        if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

                if (err->error)
                        zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
                                  "Kernel rejected neighbor update on %s: %s",
                                  r->vr->vrid, r->mvl_ifp->name,
                                  safe_strerror(-err->error));
        }

out:
        if (fd >= 0)
                close(fd);
}

static int vrrp_lb_arp_process(struct vrrp_router *r)
{
        uint8_t buf[GARP_BUFFER_SIZE];
        struct sockaddr_ll sll;
        socklen_t slen = sizeof(sll);
        ssize_t len;

        len = recvfrom(r->sock_arp, buf, sizeof(buf), 0,
                       (struct sockaddr *)&sll, &slen);
        if (len <= 0)
                return 0;

        if (sll.sll_pkttype == PACKET_OUTGOING)
                return 0;

        if ((size_t)len < sizeof(struct ether_header) + sizeof(struct arphdr))
                return 0;

        struct ether_header *eth = (struct ether_header *)buf;
        if (ntohs(eth->ether_type) != ETHERTYPE_ARP)
                return 0;

        struct arphdr *arph = (struct arphdr *)(buf + sizeof(struct ether_header));
        if (ntohs(arph->ar_op) != ARPOP_REQUEST
            || ntohs(arph->ar_pro) != ETHERTYPE_IP || arph->ar_hln != ETH_ALEN
            || arph->ar_pln != sizeof(struct in_addr))
                return 0;

        uint8_t *ptr = (uint8_t *)(arph + 1);
        uint8_t sender_mac[ETH_ALEN];
        struct in_addr sip;
        struct in_addr tip;

        memcpy(sender_mac, ptr, ETH_ALEN);
        ptr += ETH_ALEN;
        memcpy(&sip, ptr, sizeof(sip));
        ptr += sizeof(sip);
        ptr += ETH_ALEN; /* target hardware address */
        memcpy(&tip, ptr, sizeof(tip));

        if (!vrrp_lb_match_vip(r, &tip))
                return 0;

        bool use_master = (ntohl(sip.s_addr) & 0x1) == 0;
        struct ethaddr reply_mac;

        vrrp_mac_set_load_balance(&reply_mac, r->vr->vrid, use_master);

        memcpy(eth->ether_dhost, sender_mac, ETH_ALEN);
        memcpy(eth->ether_shost, reply_mac.octet, ETH_ALEN);

        arph->ar_op = htons(ARPOP_REPLY);
        ptr = (uint8_t *)(arph + 1);
        memcpy(ptr, reply_mac.octet, ETH_ALEN);
        ptr += ETH_ALEN;
        memcpy(ptr, &tip, sizeof(tip));
        ptr += sizeof(tip);
        memcpy(ptr, sender_mac, ETH_ALEN);
        ptr += ETH_ALEN;
        memcpy(ptr, &sip, sizeof(sip));

        if (sendto(r->sock_arp, buf, len, 0, (struct sockaddr *)&sll,
                   sizeof(sll)) < 0)
                zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
                          "Failed to send ARP reply on %s: %s",
                          r->vr->vrid, r->mvl_ifp->name, safe_strerror(errno));

        vrrp_lb_neigh_update(r, &sip, &reply_mac);

        return 0;
}

static int vrrp_lb_arp_read(struct thread *thread)
{
        struct vrrp_router *r = THREAD_ARG(thread);

        r->t_arp_read = NULL;

        if (!r->vr->load_balance || r->family != AF_INET)
                return 0;

        if (r->fsm.state == VRRP_STATE_MASTER)
                vrrp_lb_arp_process(r);

        if (r->sock_arp >= 0)
                thread_add_read(master, vrrp_lb_arp_read, r, r->sock_arp,
                                &r->t_arp_read);

        return 0;
}

int vrrp_lb_arp_start(struct vrrp_router *r)
{
        struct sockaddr_ll sll;

        if (!r->vr->load_balance || r->family != AF_INET)
                return 0;

        if (!r->mvl_ifp || r->mvl_ifp->ifindex <= 0) {
                zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
                          "Unable to start ARP listener; no interface for VRID %u",
                          r->vr->vrid);
                return -1;
        }

        if (r->sock_arp >= 0)
                return 0;

        r->sock_arp = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
                             htons(ETH_P_ARP));
        if (r->sock_arp < 0) {
                zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
                          "Unable to create ARP listener on %s: %s",
                          r->vr->vrid, r->mvl_ifp->name, safe_strerror(errno));
                return -1;
        }

        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ARP);
        sll.sll_ifindex = r->mvl_ifp->ifindex;

        if (bind(r->sock_arp, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
                zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
                          "Failed to bind ARP listener on %s: %s",
                          r->vr->vrid, r->mvl_ifp->name, safe_strerror(errno));
                close(r->sock_arp);
                r->sock_arp = -1;
                return -1;
        }

        thread_add_read(master, vrrp_lb_arp_read, r, r->sock_arp,
                        &r->t_arp_read);

        return 0;
}

void vrrp_lb_arp_stop(struct vrrp_router *r)
{
        THREAD_OFF(r->t_arp_read);
        if (r->sock_arp >= 0) {
                close(r->sock_arp);
                r->sock_arp = -1;
        }
}
