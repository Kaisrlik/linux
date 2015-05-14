/*
 * net/dsa/mv88e6060.c - Driver for Marvell 88e6060 switch chips
 * Copyright (c) 2008-2009 Marvell Semiconductor
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/phy.h>
#include <net/dsa.h>

#include "mv88e6xxx.h"

//netlink
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#define NETLINK_USER 0x42

struct sock *nl_sk = NULL;


static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "Hello from kernel";
    int res;

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    msg_size = strlen(msg);

    nlh = (struct nlmsghdr *)skb->data;
    printk(KERN_INFO "Netlink received msg payload: %s\n", (char *)nlmsg_data(nlh));
    pid = nlh->nlmsg_pid; /*pid of sending process */

    skb_out = nlmsg_new(msg_size, 0);

    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh), msg, msg_size);

    res = nlmsg_unicast(nl_sk, skb_out, pid);

    if (res < 0)
        printk(KERN_INFO "Error while sending bak to user\n");
}

#define MV88E6065_GLOBAL_SW_MAC_DIFF_MAC_MASK	0xef

/*Register Address*/
#define MV88E6065_REG_SW_PORT(p)		(0x8+(p))
#define MV88E6065_REG_PHY(p)		(0x0 + (p))
#define MV88E6065_REG_GLOBAL		0xe
#define MV88E6065_REG_GLOBAL2		0xf

static int reg_read(struct dsa_switch *ds, int addr, int reg)
{
	struct mii_bus *bus = dsa_host_dev_to_mii_bus(ds->master_dev);

	if (bus == NULL)
		return -EINVAL;

	return mdiobus_read(bus, ds->pd->sw_addr + addr, reg);
}

#define MV88E6065_REG_READ(addr, reg)					\
	({							\
		int __ret;					\
								\
		__ret = reg_read(ds, addr, reg);		\
		if (__ret < 0)					\
			return __ret;				\
		__ret;						\
	})


static int reg_write(struct dsa_switch *ds, int addr, int reg, u16 val)
{
	struct mii_bus *bus = dsa_host_dev_to_mii_bus(ds->master_dev);

	if (bus == NULL)
		return -EINVAL;

	return mdiobus_write(bus, ds->pd->sw_addr + addr, reg, val);
}

#define MV88E6065_REG_WRITE(addr, reg, val)				\
	({							\
		int __ret;					\
								\
		__ret = reg_write(ds, addr, reg, val);		\
		if (__ret < 0)					\
			return __ret;				\
	})

static char *mv88e6065_probe(struct device *host_dev, int sw_addr)
{
	struct mii_bus *bus = dsa_host_dev_to_mii_bus(host_dev);
	int ret;

	if (bus == NULL)
		return NULL;
	ret = mdiobus_read(bus, sw_addr + MV88E6065_REG_SW_PORT(0), 0x03);

	if (ret >= 0) {
		if ((ret & 0xfff0) == 0x0650)
			return "Marvell 88E6065";
	}

	return NULL;
}

static int mv88e6065_switch_reset(struct dsa_switch *ds)
{
	int i;
	int ret;
	unsigned long timeout;

	/* Set all ports to the disabled state. */
	for (i = 0; i < 6; i++) {
		ret = MV88E6065_REG_READ(MV88E6065_REG_SW_PORT(i), 0x04);
		MV88E6065_REG_WRITE(MV88E6065_REG_SW_PORT(i), 0x04, ret & 0xfffc);
	}

	/* Wait for transmit queues to drain. */
	usleep_range(2000, 4000);

	/* Reset the switch. */
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x0a, 0xa130);

	/* Wait up to one second for reset to complete. */
	timeout = jiffies + 1 * HZ;
	while (time_before(jiffies, timeout)) {
		ret = MV88E6065_REG_READ(MV88E6065_REG_GLOBAL, 0x00);
		if ((ret & 0x8000) == 0x0000)
			break;

		usleep_range(1000, 2000);
	}
	if (time_after(jiffies, timeout))
		return -ETIMEDOUT;

	return 0;
}


static void mv88e6065_setup_priv(struct dsa_switch *ds)
{
	struct mv88e6xxx_priv_state *ps = ds_to_priv(ds);

	mutex_init(&ps->smi_mutex);
	mutex_init(&ps->stats_mutex);
	mutex_init(&ps->phy_mutex);
}



//TODO nastaveni pro firmu jinak OK.
static int mv88e6065_setup_global(struct dsa_switch *ds)
{
	/* Disable discarding of frames with excessive collisions,
	 * set the maximum frame size to 1536 bytes, and mask all
	 * interrupt sources. Counting all frames.
	 */
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x04, 0x000);

	/* Enable automatic address learning, set the address
	 * database size to 1024 entries, and set the default aging
	 * time to 5 minutes.
	 */

	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x0a, 0x2130);


	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x07, 0x0003);
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x08, 0x0003);


	return 0;
}

static int mv88e6065_setup_port(struct dsa_switch *ds, int p)
{
	int addr = MV88E6065_REG_SW_PORT(p);

	/* MAC Forcing register: don't force link, speed, duplex
	 * or flow control state to any particular values on physical
	 * ports, but force the CPU port and all DSA ports to 100Mb/s and full duplex.
	 */
	MV88E6065_REG_WRITE(addr, 0x01, 0x003d);
//	MV88E6065_REG_WRITE(addr, 0x01, 0x000d);
//	MV88E6065_REG_WRITE(addr, 0x01, 0x0000);
	/* Do not force flow control, disable Ingress and Egress
	 * Header tagging, disable VLAN tunneling, and set the port
	 * state to Forwarding.  Additionally, if this is the CPU
	 * port, enable Ingress and Egress Trailer tagging mode.
	 */
	MV88E6065_REG_WRITE(addr, 0x04, 0x0003);
	MV88E6065_REG_WRITE(addr, 0x04, 0x100f);

	return 0;
}

static int mv88e6065_setup(struct dsa_switch *ds)
{
	int i;
	int ret;


	mv88e6065_setup_priv(ds);

	ret = mv88e6065_switch_reset(ds);
	if (ret < 0)
		return ret;

	/* @@@ initialise atu */

	ret = mv88e6065_setup_global(ds);
	if (ret < 0)
		return ret;

	for (i = 0; i < 6; i++) {
		ret = mv88e6065_setup_port(ds, i);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/**
 * Set MAC address on all ports. All these ports have same MAC address.
 */
static int mv88e6065_set_addr(struct dsa_switch *ds, u8 *addr)
{
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x01, ((addr[0] << 8) & MV88E6065_GLOBAL_SW_MAC_DIFF_MAC_MASK) | addr[1]); //
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x02, (addr[2] << 8) | addr[3]);
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x03, (addr[4] << 8) | addr[5]);

	return 0;
}

/**
 * Check port address.
 */
static int mv88e6065_port_to_phy_addr(int port)
{
	if (port >= 0 && port <= 5)
		return port;
	return -1;
}

static int mv88e6065_phy_read(struct dsa_switch *ds, int port, int regnum)
{
	int addr;

	addr = mv88e6065_port_to_phy_addr(port);
	if (addr == -1)
		return 0xffff;

	return reg_read(ds, addr, regnum);
}

static int
mv88e6065_phy_write(struct dsa_switch *ds, int port, int regnum, u16 val)
{
	int addr;

	addr = mv88e6065_port_to_phy_addr(port);
	if (addr == -1)
		return 0xffff;

	return reg_write(ds, addr, regnum, val);
}

static void mv88e6065_poll_link(struct dsa_switch *ds)
{
	int i;
	for (i = 0; i < DSA_MAX_PORTS; i++) {
		struct net_device *dev;
		int uninitialized_var(port_status);
		int link;
		int speed;
		int duplex;
		int fc;

		dev = ds->ports[i];
		if (dev == NULL)
			continue;

		link = 0;
		if (dev->flags & IFF_UP) {
			port_status = reg_read(ds, i + 0x8, 0x00);

			if (port_status < 0)
				continue;

			link = !!(port_status & 0x2000);
		}

		if (!link) {
			if (netif_carrier_ok(dev)) {
				netdev_info(dev, "link down\n");
				netif_carrier_off(dev);
			}
			continue;
		}

		speed = (port_status & 0x0100) ? 100 : 10;
		duplex = (port_status & 0x0200) ? 1 : 0;
		if (duplex)
			fc = ((port_status & 0x0008) == 0x0008) ? 1 : 0;
		else
			fc = ((port_status & 0x0004) == 0x0004) ? 1 : 0;

		if (!netif_carrier_ok(dev)) {
			netdev_info(dev,
				    "link up, %d Mb/s, %s duplex, flow control %sabled\n",
				    speed,
				    duplex ? "full" : "half",
				    fc ? "en" : "dis");
			netif_carrier_on(dev);
		}
	}
}



static int mv88e6065_rwr(struct dsa_switch *ds, int addr, int reg, int val, int mask){
	int x = reg_read(ds, addr, reg);
	printk("%s addr 0x%x:0x%x  reg 0x%x\n",__FUNCTION__, addr, reg, x);
	x &= mask;
	if (val & mask)
		return -EINVAL;

	printk("%s addr 0x%x:0x%x  reg 0x%x\n",__FUNCTION__, addr, reg, x|val);
	MV88E6065_REG_WRITE(addr, reg,  x | val);

	return 0;
}

/**
 * Enable port base vlan
 * @param enabled_port 1 for enable connect port with port 0, 2 for port 1, 4 for port 2, .... 
 *   exapmle : mv88e6065_port_base_vlan(ds, port, 0x1f - 4 - (1 < port)); //disable link between port port and port 2
 *   exapmle : mv88e6065_port_base_vlan(ds, port, 0x1f - 4); //disable link between port port and port 2 with looback
 */
static int mv88e6065_port_base_vlan(struct dsa_switch *ds, int port, int enabled_port){
	/*Disable 802.1Q on port port*/
	mv88e6065_rwr(ds, port + 0x8, 0x08, 0, 0xf3ff);
	/*Enable port base VLAN for specific ports*/
	return mv88e6065_rwr(ds, port + 0x8, 0x06, enabled_port, 0xffe0);
}

static int mv88e6065_port_enable(struct dsa_switch *ds, int port, struct phy_device *phy)
{
	/*PHY reg 100MB full, port normal aneg unchange untagged frames*/
	MV88E6065_REG_WRITE(port, 0x04, 0x00e1);
	MV88E6065_REG_WRITE(port, 0x00, 0x3300);
	return 0;
}

static int mv88e6065_port_disable(struct dsa_switch *ds, int port, struct phy_device *phy)
{
	/*Port shutdown*/
	MV88E6065_REG_WRITE(port, 0x00, 0x0800);
	return 0;
}


static struct mv88e6xxx_hw_stat mv88e6065_hw_stats[] = {
	{ "in_good_octets", 4, 0x00, },
	{ "in_bad_octets", 4, 0x02, },
	{ "in_unicast", 4, 0x04, },
	{ "in_broadcasts", 4, 0x06, },
	{ "in_multicasts", 4, 0x07, },
	{ "in_pause", 4, 0x16, },
	{ "in_undersize", 4, 0x18, },
	{ "in_fragments", 4, 0x19, },
	{ "in_oversize", 4, 0x1a, },
	{ "in_jabber", 4, 0x1b, },
	{ "in_rx_error", 4, 0x1c, },
	{ "in_fcs_error", 4, 0x1d, },
	{ "out_octets", 4, 0x0e, },
	{ "out_unicast", 4, 0x10, },
	{ "out_multicasts", 4, 0x12, },
	{ "out_broadcasts", 4, 0x13, },
	{ "out_pause", 4, 0x15, },
	{ "excessive", 4, 0x11, },
	{ "deferred", 4, 0x05, },
	{ "single", 4, 0x14, },
	{ "multiple", 4, 0x17, },
	{ "late", 4, 0x1f, },
	{ "hist_64bytes", 4, 0x08, },
	{ "hist_65_127bytes", 4, 0x09, },
	{ "hist_128_255bytes", 4, 0x0a, },
	{ "hist_256_511bytes", 4, 0x0b, },
	{ "hist_512_1023bytes", 4, 0x0c, },
	{ "hist_1024_max_bytes", 4, 0x0d, },
};


static void mv88e6065_get_strings(struct dsa_switch *ds, int port, uint8_t *data)
{
	mv88e6xxx_get_strings(ds, ARRAY_SIZE(mv88e6065_hw_stats), mv88e6065_hw_stats, port, data);
}


static int mv88e6065_wait(struct dsa_switch *ds, int addr)
{
	int ret;
	int i;

	/*check if stats is not busy*/
	for (i = 0; i < 10; i++) {
		ret = reg_read(ds, MV88E6065_REG_GLOBAL, addr);
		if ((ret & 0x8000) == 0)
			return 0;
	}

	return -EBUSY;
}


static int mv88e6065_vtu_read(struct dsa_switch *ds, uint16_t *vlan){
	int ret, i;

	while(true) {
		MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x05, 0x4);
		ret = mv88e6065_wait(ds, 0x05);
		if (ret < 0)
			return ret;

		ret = reg_read(ds, MV88E6065_REG_GLOBAL, 0x06);
		vlan[i++] = ret & 0x0fff;
		if ((ret & 0x1000) == 0x1000)
			break;
	}

	return 0;
}

static int mv88e6065_vtu_load(struct dsa_switch *ds, int port, int vlan){
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x06, vlan | 0x1000);
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x05, 0x3000 | port);
	return 0;
}


static int mv88e6065_vtu_set_port_forwarding(struct dsa_switch *ds, int port){
	int ret;
	/*set port to learnig state and to tagging frames*/
	if (port < 4) {
		ret = reg_read(ds, MV88E6065_REG_GLOBAL, 0x07);
		MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x07, (ret & !(0xf << (port*4))) & (0xa << (port*4)) );
	}else{
		ret = reg_read(ds, MV88E6065_REG_GLOBAL, 0x08);
		MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x08, (ret & !(0xf << ((port-4)*4))) & (0xa << ((port-4)*4)) );
	}
	return 0;
}

static int mv88e6065_vtu_set_all_ports_forwarding(struct dsa_switch *ds, int port){
	/*set all ports to learnig state and to tagging frames*/
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x07, 0xaaaa );
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x08, 0x00aa );
	return 0;
}

static int mv88e6065_stats_snapshot(struct dsa_switch *ds, int port)
{
	int ret;

	/* Snapshot the hardware statistics counters for this port. */
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x1d, 0xdb00 | (port << 5) );

	/* Wait for the snapshotting to complete. */
	ret = mv88e6065_wait(ds, 0x1d);
	if (ret < 0)
		return ret;

	return 0;
}


static int mv88e6065_stats_read(struct dsa_switch *ds, int stat, u32 *val)
{
	u32 _val;
	int ret;

	*val = 0;

	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x1d, 0xcc00 | stat);

	ret = mv88e6065_wait(ds, 0x1d);
	if (ret < 0)
		return ret;

	ret = reg_read(ds, MV88E6065_REG_GLOBAL, 0x1e);
	if (ret < 0)
		return ret;

	_val = ret << 16;

	ret = reg_read(ds, MV88E6065_REG_GLOBAL, 0x1f);
	if (ret < 0)
		return ret;

	*val = _val | ret;

	return 0;
}



static void mv88e6065_get_ethtool_stats(struct dsa_switch *ds, int port, uint64_t *data)
{
	struct mv88e6xxx_priv_state *ps = ds_to_priv(ds);
	int ret;
	int i;

	mutex_lock(&ps->stats_mutex);

	ret = mv88e6065_stats_snapshot(ds, port);
	if (ret < 0) {
		mutex_unlock(&ps->stats_mutex);
		return;
	}

	/* Read each of the counters. */
	for (i = 0; i < ARRAY_SIZE(mv88e6065_hw_stats); i++) {
		struct mv88e6xxx_hw_stat *s = mv88e6065_hw_stats + i;
		u32 low;
		u32 high = 0;

		mv88e6065_stats_read(ds, s->reg, &low);
		if (s->sizeof_stat == 4)
			mv88e6065_stats_read(ds, s->reg - 1, &high);

		data[i] = (((u64)high) << 16) | low;
	}
	
	mutex_unlock(&ps->stats_mutex);

}

static int mv88e6065_get_sset_count(struct dsa_switch *ds)
{
	return ARRAY_SIZE(mv88e6065_hw_stats);
}
static int mv88e6065_set_eeprom(struct dsa_switch *ds, struct ethtool_eeprom *eeprom, u8 *data)
{
	return 0;
}

static int mv88e6065_get_eeprom(struct dsa_switch *ds, struct ethtool_eeprom *eeprom, u8 *data)
{
	return 0;
}

struct dsa_switch_driver mv88e6065_switch_driver = {
	.priv_size		= sizeof(struct mv88e6xxx_priv_state),
	.tag_protocol	= DSA_TAG_PROTO_TRAILER,
	.probe		= mv88e6065_probe,
	.setup		= mv88e6065_setup,
	.set_addr	= mv88e6065_set_addr,
	.phy_read	= mv88e6065_phy_read,
	.phy_write	= mv88e6065_phy_write,
	.poll_link	= mv88e6065_poll_link,
	/*port setting*/
	.port_enable	 = mv88e6065_port_enable,
	.port_disable	 = mv88e6065_port_disable,
	/*stats*/
	.get_strings			= mv88e6065_get_strings,
	.get_ethtool_stats	= mv88e6065_get_ethtool_stats,
	.get_sset_count		= mv88e6065_get_sset_count,
	/* Register access.*/
	.get_regs_len	= mv88e6xxx_get_regs_len,
	.get_regs	= mv88e6xxx_get_regs,
	/*eeprom ops*/
	.get_eeprom             = mv88e6065_get_eeprom,
	.set_eeprom             = mv88e6065_set_eeprom,
};

static struct netlink_kernel_cfg cfg = {
	.groups	= 1,
	.input	= nl_recv_msg,
};

static int __init mv88e6065_init(void)
{
	register_switch_driver(&mv88e6065_switch_driver);
	
	/*Register netlink*/
   nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	if (!nl_sk) {
		printk(KERN_ALERT "Error creating socket.\n");
		return -ENOMEM;
	}

	return 0;
}
module_init(mv88e6065_init);

static void __exit mv88e6065_cleanup(void)
{
	unregister_switch_driver(&mv88e6065_switch_driver);
	/*unregister netlink*/
	netlink_kernel_release(nl_sk);
}
module_exit(mv88e6065_cleanup);

MODULE_DESCRIPTION("Driver for Marvell 88E6065 ethernet switch chip");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:mv88e6065");
