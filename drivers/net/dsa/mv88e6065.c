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

/*Sysfs*/
#include <linux/kernel.h>
#include <linux/string.h>

#define to_mv_obj(x) container_of(x, struct mv_priv, kobj)
#define to_mv_attr(x) container_of(x, struct mv_attribute, attr)

struct mv_ops{
	int op;
	int port;
	int data;
	int data2;
};
struct mv_ops mv_ops;

struct mv_priv{
	struct kobject *kobj;
	struct dsa_swich *ds;
};
struct mv_priv mv_priv;

struct mv_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mv_priv *priv, struct mv_attribute *attr, char *buf);
	ssize_t (*store)(struct mv_priv *priv, struct mv_attribute *attr, const char *buf, size_t count);
};

static int mv88e6065_msg_process(struct dsa_switch *ds, const char *buf, size_t count);
static int mv88e6065_read_all(struct dsa_switch *ds);


static ssize_t usb_dsa_store(struct mv_priv *ds,
		struct mv_attribute *attr, const char *buf, size_t count)
{
	printk("Store!!\n");
	mv88e6065_msg_process(ds->ds, buf, count);
	return count;
}

static ssize_t usb_dsa_show(struct mv_priv *ds,
		struct mv_attribute *attr, char *buf)
{
	printk("Read !!\n");
	printk("Read %x !!\n", ds->ds);
	mv88e6065_read_all(ds->ds);
	return scnprintf(buf, PAGE_SIZE, "usb_dsa_binding.\n");
}

static void driver_release(struct kobject *kobj)
{
}

static ssize_t usb_dsa_attr_show(struct kobject *kobj,
	struct attribute *attr, char *buf)
{
	struct mv_attribute *attribute;
	struct mv_priv *ds;

	attribute = to_mv_attr(attr);
	ds = to_mv_obj(kobj);

	if (!attribute->show)
		return -EINVAL;

	return attribute->show(ds, attribute, buf);
}
static ssize_t usb_dsa_attr_store(struct kobject *kobj,
		struct attribute *attr, const char *buf, size_t len)
{
	printk("Store1!!\n");
	struct mv_attribute *attribute;
	struct mv_priv *ds;

	attribute = to_mv_attr(attr);
	ds = to_mv_obj(kobj);

	if (!attribute->store)
		return -EINVAL;
	return attribute->store(ds, attribute, buf, len);
}

static struct mv_attribute mv_attribute =  __ATTR(swtichcntrl, 0664, usb_dsa_show, usb_dsa_store);
static struct attribute *mv_default_attrs[] = {
	&mv_attribute.attr,
	NULL,
};
static const struct sysfs_ops dsa_bind_sysfs_ops = {
	.show   = usb_dsa_attr_show,
	.store  = usb_dsa_attr_store,
};
static struct kobj_type mv_bind_ktype = {
	.sysfs_ops      = &dsa_bind_sysfs_ops,
	.release        = driver_release,
	.default_attrs  = mv_default_attrs,
};
static struct attribute_group mv_attr_group = {
        .attrs = mv_default_attrs,
        .name = "mv88e6065",
};

#define MV88E6065_GLOBAL_SW_MAC_DIFF_MAC_MASK	0xef

/*Register Address*/
#define MV88E6065_REG_SW_PORT(p)		(0x8+(p))
#define MV88E6065_REG_PHY(p)		(0x0 + (p))
#define MV88E6065_REG_GLOBAL		0xe
#define MV88E6065_REG_GLOBAL2		0xf
#define MV88E6065_MAX_PORTS		0x06

static int reg_read(struct dsa_switch *ds, int addr, int reg)
{
	struct mii_bus *bus = dsa_host_dev_to_mii_bus(ds->master_dev);

	if (bus == NULL)
		return -EINVAL;

	int ret = mdiobus_read(bus, ds->pd->sw_addr + addr, reg);

	return ret;
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

	int ret = mdiobus_write(bus, ds->pd->sw_addr + addr, reg, val);

	return ret;
}
//

#define MV88E6065_REG_WRITE(addr, reg, val)				\
	({							\
		int __ret;					\
		printk("WRITE add:%x reg:%x val:%x\n", addr, reg, val);						\
		__ret = reg_write(ds, addr, reg, val);		\
		if (__ret < 0)					\
			return __ret;				\
	})

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

static int mv88e6065_wait(struct dsa_switch *ds, int addr)
{
	int ret;
	int i;

	/*check if stats is not busy*/
	for (i = 0; i < 10; i++) {
		ret = reg_read(ds, MV88E6065_REG_GLOBAL, addr);
		printk("BUSY 0x%x\n", ret);
		if ((ret & 0x8000) == 0)
			return 0;
	}

	printk("BUSYEror GLOABAL 0x%x\n", addr);
	return -EBUSY;
}
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


static int mv88e6065_setup_global(struct dsa_switch *ds)
{
	/* Disable discarding of frames with excessive collisions,
	 * set the maximum frame size to 1536 bytes, and mask all
	 * interrupt sources. Counting all frames.
	 */
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x04, 0x000);
	/*Enable VTU int*/
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x04, 0x0030);

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
//	MV88E6065_REG_WRITE(addr, 0x04, 0x0003);
	MV88E6065_REG_WRITE(addr, 0x04, 0x100f); //engress untagged
//	MV88E6065_REG_WRITE(addr, 0x04, 0x200f); //engress tagged

	MV88E6065_REG_WRITE(addr, 0x06, 0x1f); //map all/all
	mv88e6065_rwr(ds, addr, 0x08, 0x0400, 0xf0ff); //ingress fallvack, no discarting frames
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

	/*Sysfs*/
	mv_priv.ds = ds;

	mv_priv.kobj = kobject_create_and_add("MV88E6065_SETUP", NULL);

	ret = sysfs_create_group(mv_priv.kobj, &mv_attr_group);
	if (ret) {
		printk(KERN_ERR "ksm: register sysfs failed\n");
		return -ENOMEM;
	}
/*	mv_priv.ds = ds;
	//mv_priv.kobj.kset = kset_create_and_add("MV88E6065_SETUP", NULL, kobject_get(&ds->master_dev.kobj));
	mv_priv.kobj.kset = NULL;
	if (!mv_priv.kobj.kset){
		ret = -ENOMEM;
		goto free;
	}

	ret = kobject_init_and_add(&mv_priv.kobj, &mv_bind_ktype, NULL, "setup");
	if (ret)
		goto free_kobj;

	return 0;

free_kobj:
	kobject_put(&mv_priv.kobj);
free:
//	kfree(priv);
	return ret;*/
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





static int mv88e6065_vtu_read(struct dsa_switch *ds){
	int ret, i = 0;
	mv88e6065_wait(ds, 0x05);

	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x06, 0xffff);
	while(true) {
		i++;
		MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x05, 0x4000 | 0x8000);
		ret = reg_read(ds, MV88E6065_REG_GLOBAL, 0x06);
		printk("0x%x ", ret);
		ret = mv88e6065_wait(ds, 0x05);
		if (ret < 0)
			return ret;

		ret = reg_read(ds, MV88E6065_REG_GLOBAL, 0x06);

		if (i > 0x1001){
			printk("overflow \n");
			return -EINVAL;
		}
		if (((ret & 0x0fff) == 0xfff) && ((ret & 0x1000) == 0x0000))
			break;
		if ((ret & 0x1000) == 0x0)
			continue;
		printk("VLAn 0x%x \n", ret);
	}

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


static int mv88e6065_add_vlan_port(struct dsa_switch *ds, int vlanid, int port){
	int x1, x2, x3, portstate1 = 0, portstate2 = 0;
	/*TODO get next, read 0x7 0x8 ... add port*/
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x06, vlanid - 1 );
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x05, 0x4000 | 0x8000);
	mv88e6065_wait(ds, 0x05);
	portstate1 = reg_read(ds, MV88E6065_REG_GLOBAL, 0x07);
	portstate2 = reg_read(ds, MV88E6065_REG_GLOBAL, 0x08);

	/*update and write back*/
	if (port < 4){
		portstate1 &= (!(0xf < (4*port)));
		portstate1 |= 0xe << (4 * port);
	}else{
		portstate2 &= (!(0xf < (4*(port-4))));
		portstate2 |= 0xe << (4 * (port-4));
	}
	mv88e6065_wait(ds, 0x5);

	printk("ADD vlan 7:%x 8:%x \n", portstate1, portstate2);
	/*Forwarding, Tagged frames or Disabled. umodified frames*/
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x08, portstate2);
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x07, portstate1);

	/*vlan id, Valid bit 1 -> Load op*/
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x06, vlanid | 0x1000);

	/*Load or Purge, DBNum 0*/
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x05, 0x3000 | 0x8000);

	mv88e6065_wait(ds, 0x5);
	x1 = reg_read(ds, MV88E6065_REG_GLOBAL, 0x5);
	x2 = reg_read(ds, MV88E6065_REG_GLOBAL, 0x6);
	x3 = reg_read(ds, MV88E6065_REG_GLOBAL, 0x7);

	printk("VLAN ADD %x %x %x\n", x1, x2, x3);
}


static int mv88e6065_add_vlan(struct dsa_switch *ds, int vlanid, int ports){
	int i, x1, x2, x3, portstate1 = 0, portstate2 = 0;

	if (vlanid > 0x0fff)
		return -EINVAL;

	for (i = 0; i < MV88E6065_MAX_PORTS; i++) {
		if (ports & (1 << i)){
				MV88E6065_REG_WRITE(i + 0x8, 0x04, 0x200f); //engress tagged
			if (i < 4)
				portstate1 |= 0xe << (4 * i);
			else
				portstate2 |= 0xe << (4 * (i-4));
				//portstate2 |= 0xf << (4 * (i-4));
		}else{
			if (i < 4)
				portstate1 |= 0xf << (4 * i);
			else
				portstate2 |= 0xf << (4 * (i-4));
		}
	}
	printk("ADD vlan 7:%x 8:%x \n", portstate1, portstate2);

	mv88e6065_wait(ds, 0x5);

	/*Forwarding, Tagged frames or Disabled. umodified frames*/
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x08, portstate2);
		int x = reg_read(ds, MV88E6065_REG_GLOBAL, 0x08);
		printk("i8 %x\n", x);
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x07, portstate1);
		x = reg_read(ds, MV88E6065_REG_GLOBAL, 0x07);
		printk("i7 %x\n", x);

	/*vlan id, Valid bit 1 -> Load op*/
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x06, vlanid | 0x1000);
		x = reg_read(ds, MV88E6065_REG_GLOBAL, 0x6);
		printk("i6 %x\n", x);

	/*Load or Purge, DBNum 0*/
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x05, 0x3000 | 0x8000);
		x = reg_read(ds, MV88E6065_REG_GLOBAL, 0x5);
		printk("i5 %x\n", x);

	mv88e6065_wait(ds, 0x5);
	x1 = reg_read(ds, MV88E6065_REG_GLOBAL, 0x5);
	x2 = reg_read(ds, MV88E6065_REG_GLOBAL, 0x6);
	x3 = reg_read(ds, MV88E6065_REG_GLOBAL, 0x7);

	printk("VLAN ADD %x %x %x\n", x1, x2, x3);
}


static int mv88e6065_remove_vlan(struct dsa_switch *ds, int vlanid, int ports){
	mv88e6065_wait(ds, 0x5);
	/*vlan id, Valid bit 0 -> Purge op*/
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x06, vlanid);

	/*Load or Purge, DBNum 0*/
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x05, 0x3000 | 0x8000);
}

static int mv88e6065_flush_vlan(struct dsa_switch *ds){
	mv88e6065_wait(ds, 0x5);

	/*Flush*/
	MV88E6065_REG_WRITE(MV88E6065_REG_GLOBAL, 0x05, 0x1000 | 0x8000);
}

static int mv88e6065_port_enable(struct dsa_switch *ds, int port, struct phy_device *phy)
{
	/*PHY reg 100MB full, port normal aneg unchange untagged frames*/
	MV88E6065_REG_WRITE(port, 0x04, 0x01e1);
	MV88E6065_REG_WRITE(port, 0x00, 0x3300 | 0x8000);
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

static void mv88e6065_set_cross(struct dsa_switch *ds, int port, int data){
	if (data == 100){
		mv88e6065_rwr(ds, port, 0x10, 0x0030, 0xffcf);
		printk("Port %x cross up\n", port);
	}else{
		mv88e6065_rwr(ds, port, 0x10, 0x0000, 0xffcf);
		printk("Port %x cross down\n", port);
	}
}

static void mv88e6065_set_speed(struct dsa_switch *ds, int port, int speed, int dplx){
	int x = 0, y = 0;

	if (speed == 100){
		x |= 0xa000;
		y |= 0x0001;
	}else{
		x |= 0x8000;
		y |= 0x0000;
	}
	if (dplx){
		x |= 0x0100;
		y |= 0x000c;
	}else{
		x |= 0x0000;
		y |= 0x0004;
	}

	mv88e6065_rwr(ds, port, 0x00, x, 0x46ff);
	mv88e6065_rwr(ds, port + 0x8, 0x01, y, 0xfff0);

	//with aneg

	MV88E6065_REG_WRITE(port, 0x00, 0x0800);
	if (speed == 100){
		if (dplx)
			MV88E6065_REG_WRITE(port, 0x04, 0x0101);
		else
			MV88E6065_REG_WRITE(port, 0x04, 0x0081);


	}else{
		if (dplx)
			MV88E6065_REG_WRITE(port, 0x04, 0x0041);
		else
			MV88E6065_REG_WRITE(port, 0x04, 0x0021);
	}
	MV88E6065_REG_WRITE(port, 0x00, 0x3300 | 0x8000);
}

static void mv88e6065_set_aneg(struct dsa_switch *ds, int port, int data){
	if (data){
		//mv88e6065_rwr(ds, port, 0x00, 0x9300, 0x65ff);
		mv88e6065_rwr(ds, port + 0x8, 0x01, 0x0003, 0xfff0);
		/*Port shutdown*/
		MV88E6065_REG_WRITE(port, 0x00, 0x0800);
		/*PHY reg 100MB full, port normal aneg unchange untagged frames*/
		MV88E6065_REG_WRITE(port, 0x04, 0x01e1);
		MV88E6065_REG_WRITE(port, 0x00, 0x3300 | 0x8000);
		printk("Port %x aneg on\n", port);
	}else{
		mv88e6065_rwr(ds, port, 0x00, 0x8000, 0x67ff);
		mv88e6065_rwr(ds, port + 0x8, 0x01, 0x0003, 0xfff0);
		printk("Port %x aneg off\n", port);
	}

}
static void mv88e6065_port_state(struct dsa_switch *ds){
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
			netdev_info(dev, "link down\n");
			continue;
		}

		speed = (port_status & 0x0100) ? 100 : 10;
		duplex = (port_status & 0x0200) ? 1 : 0;
		if (duplex)
			fc = ((port_status & 0x0008) == 0x0008) ? 1 : 0;
		else
			fc = ((port_status & 0x0004) == 0x0004) ? 1 : 0;

		netdev_info(dev,
			    "link up, %d Mb/s, %s duplex, flow control %sabled\n",
			    speed,
			    duplex ? "full" : "half",
			    fc ? "en" : "dis");
	}
}

static void mv88e6065_poll_link(struct dsa_switch *ds)
{
	int i;
	for (i = 0; i < DSA_MAX_PORTS; i++) {
		struct net_device *dev;
		int uninitialized_var(port_status);
		int uninitialized_var(port_status2);
		int uninitialized_var(port_status3);
		int link;
		int speed;
		int duplex;
		int fc;

		dev = ds->ports[i];
		if (dev == NULL)
			continue;

		link = 0;
		if (dev->flags & IFF_UP) {
//			port_status3 = reg_read(ds, i+0x8 , 0x1);
//		printk("state1 0x%x\n", port_status3);
			port_status2 = reg_read(ds, i , 0x11);
//		printk("phy 0x%x\n", port_status2);
			port_status = reg_read(ds, i + 0x8, 0x00);
//		printk("0x%x\n", port_status);
			if (port_status < 0)
				continue;

//			link = !!(port_status & 0x2000);
			link = !!(port_status2 & 0x0400);
		}

		if (!link) {
			if (netif_carrier_ok(dev)) {
				netdev_info(dev, "link down\n");
				netif_carrier_off(dev);
			}
			continue;
		}

		speed = (port_status & 0x0100) ? 100 : 10;
		//duplex = (port_status2 & 0x2000) ? 1 : 0;
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

	switch(mv_ops.op){
case 1:
//		mv88e6065_vtu_read(ds);
		mv88e6065_port_state(ds);
		break;
case 2:
		mv88e6065_flush_vlan(ds);
		break;
case 3:
		mv88e6065_add_vlan(ds, mv_ops.data, 0x1f); //TODO mv88e6065_add_vlan_port
		break;
case 4:
		mv88e6065_set_speed(ds, mv_ops.port, mv_ops.data, mv_ops.data2);
		break;
case 5:
//		mv88e6065_set_dplx(ds, mv_ops.port, mv_ops.data);
		break;
case 6:
		mv88e6065_set_aneg(ds, mv_ops.port, mv_ops.data);
		break;
	}
	mv_ops.op = 0;

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

	/*Sysfs*/
//	kset_unregister(mv_priv.kobj.kset);
//	kobject_put(&mv_priv.kobj);
}
module_exit(mv88e6065_cleanup);

/*Sysfs ops*/
static int mv88e6065_read_all(struct dsa_switch *ds){
//	mv88e6065_vtu_read(ds);
	mv_ops.op = 1;
	return 0;
}
/*Sysfs ops*/
static int mv88e6065_msg_process(struct dsa_switch *ds, const char *buf, size_t count){
	char *ret, **s, *token;
	int port , reti;
	int temp;

	s = &buf;
	token = strsep(s, " ");
	reti = kstrtoint(token, 0x10, &port);
	printk("PORT number: %x\n", port);
	mv_ops.port = port;
	
	ret = strstr(buf, "vlanflush");
	printk("%s\n", buf);
	if (ret != NULL)
		mv_ops.op = 2;
//		mv88e6065_flush_vlan(ds);
	
	ret = strstr(buf, "vlan");
	printk("%s\n", buf);
	if (ret != NULL){
		s = &ret;
		strsep(s, " ");
		token = strsep(s, " ");
		printk("VLAN: %s \n", token);
		reti = kstrtoint(token, 0x10, &temp);
		mv_ops.data = temp;
		mv_ops.op = 3;
//		mv88e6065_add_vlan(ds, temp, 0x1f); //TODO mv88e6065_add_vlan_port
	}

	ret = strstr(buf, "speed");
	if (ret != NULL){
		s = &ret;
		strsep(s, " ");
		token = strsep(s, " ");
		printk("speed: %s \n", token);
		reti = kstrtoint(token, 0xa, &temp);
		mv_ops.data = temp;
		token = strsep(s, " ");
		printk("dplx: %s \n", token);
		reti = kstrtoint(token, 0x10, &temp);
		mv_ops.data2 = temp;
		mv_ops.op = 4;
	//	mv88e6065_set_speed(ds, port, temp);
	}

	ret = strstr(buf, "aneg");
	if (ret != NULL){
		s = &ret;
		strsep(s, " ");
		token = strsep(s, " ");
		printk("aneg: %s \n", token);
		reti = kstrtoint(token, 0x10, &temp);
		mv_ops.data = temp;
		mv_ops.op = 6;
	//	mv88e6065_set_aneg(ds, port, temp);
	}
	return 0;
}

MODULE_DESCRIPTION("Driver for Marvell 88E6065 ethernet switch chip");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:mv88e6065");
