#include <sys/types.h>
#include <sys/socket.h>         /* for PF_LINK */
#include <sys/sysctl.h>
#include <sys/time.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_mib.h>

#include "cJSON.h"
#include "iftypes.h"

void doif(int ifnum, cJSON* root);
static const char * iftype(int type);
static const char * iftyped(int type);
cJSON * ifflags(uint64_t flags);
cJSON * ifhwcaps(uint64_t flags);

int
main(int argc, char **argv)
{
        int i, maxifno, retval;
        int name[6];
        size_t len;
        int c;
        void *linkmib;
        size_t linkmiblen;
        char *dname;

        name[0] = CTL_NET;
        name[1] = PF_LINK;
        name[2] = NETLINK_GENERIC;
        name[3] = IFMIB_SYSTEM;
        name[4] = IFMIB_IFCOUNT;
        len = sizeof maxifno;
        if (sysctl(name, 5, &maxifno, &len, 0, 0) < 0)
                err(EX_OSERR, "sysctl(net.link.generic.system.ifcount)");

	cJSON *root = cJSON_CreateObject();
	
	for (i = 1; i <= maxifno; i++) {
		doif(i, root);
	}

	char *jsonoutput = cJSON_Print(root);
	printf("%s\n", jsonoutput);

}

void doif(int ifnum, cJSON* root) {
	
        int i, retval;
        struct ifmibdata ifmd;
        int name[6];
        size_t len;
        int c;
        void *linkmib;
        size_t linkmiblen;
        char *dname;

	retval = 1;

        name[0] = CTL_NET;
        name[1] = PF_LINK;
        name[2] = NETLINK_GENERIC;
        len = sizeof ifmd;
        name[3] = IFMIB_IFDATA;
        name[4] = ifnum;
        name[5] = IFDATA_GENERAL;
        if (sysctl(name, 6, &ifmd, &len, 0, 0) < 0) {
                if (errno == ENOENT)
                        return;

                err(EX_OSERR, "sysctl(net.link.ifdata.%d.general)",
                    ifnum);
        }

        dname = NULL;
        len = 0;
        name[5] = IFDATA_DRIVERNAME;
        int mib[255];
        size_t mlen;
        //sysctlnametomib("net.link.generic.ifdata.0.drivername",mib,&mlen);
        if (sysctl(name, 6, NULL, &len, 0, 0) < 0) {
                warn("sysctl(net.link.ifdata.%d.drivername)", ifnum);
        } else {
                if ((dname = malloc(len)) == NULL)
                        err(EX_OSERR, NULL);
                if (sysctl(name, 6, dname, &len, 0, 0) < 0) {
                        warn("sysctl(net.link.ifdata.%d.drivername)",
                            ifnum);
                        free(dname);
                        dname = NULL;
                }
        }
        cJSON* node = cJSON_CreateObject();
        cJSON_AddItemToObject(root, dname, node);
        cJSON_AddStringToObject(node, "name", dname);
        cJSON_AddStringToObject(node, "virtname", ifmd.ifmd_name);
        cJSON_AddNumberToObject(node, "flags_value", ifmd.ifmd_flags);
        cJSON_AddItemToObject(node, "flags", ifflags(ifmd.ifmd_flags)); 
        cJSON_AddNumberToObject(node, "capabilities_value", ifmd.ifmd_data.ifi_hwassist);
        cJSON_AddItemToObject(node, "capabilities", ifhwcaps(ifmd.ifmd_data.ifi_hwassist));
        cJSON_AddNumberToObject(node, "promisc_listeners", ifmd.ifmd_pcount);
        cJSON_AddNumberToObject(node, "send_queue_length", ifmd.ifmd_snd_len);
        cJSON_AddNumberToObject(node, "send_queue_drops", ifmd.ifmd_snd_drops);
        cJSON_AddStringToObject(node, "type", iftype(ifmd.ifmd_data.ifi_type));
        cJSON_AddStringToObject(node, "type_description", iftyped(ifmd.ifmd_data.ifi_type));
        cJSON_AddBoolToObject(node, "link", (ifmd.ifmd_data.ifi_link_state == LINK_STATE_UP));
        cJSON_AddNumberToObject(node, "vhid", ifmd.ifmd_data.ifi_vhid);
        cJSON_AddNumberToObject(node, "mtu", ifmd.ifmd_data.ifi_mtu);
        cJSON_AddNumberToObject(node, "metric", ifmd.ifmd_data.ifi_metric);
        cJSON_AddNumberToObject(node, "baudrate", ifmd.ifmd_data.ifi_baudrate);
        cJSON_AddNumberToObject(node, "ipackets", ifmd.ifmd_data.ifi_ipackets);
        cJSON_AddNumberToObject(node, "ierrors", ifmd.ifmd_data.ifi_ierrors);
        cJSON_AddNumberToObject(node, "ibytes", ifmd.ifmd_data.ifi_ibytes);
        cJSON_AddNumberToObject(node, "imcasts", ifmd.ifmd_data.ifi_imcasts);
        cJSON_AddNumberToObject(node, "iqdrops", ifmd.ifmd_data.ifi_iqdrops);
        cJSON_AddNumberToObject(node, "opackets", ifmd.ifmd_data.ifi_opackets);
        cJSON_AddNumberToObject(node, "oerrors", ifmd.ifmd_data.ifi_oerrors);
        cJSON_AddNumberToObject(node, "obytes", ifmd.ifmd_data.ifi_obytes);
        cJSON_AddNumberToObject(node, "omcasts", ifmd.ifmd_data.ifi_omcasts);
#ifdef _IFI_OQDROPS
        cJSON_AddNumberToObject(node, "oqdrops", ifmd.ifmd_data.ifi_oqdrops);
#endif
        cJSON_AddNumberToObject(node, "collisions", ifmd.ifmd_data.ifi_collisions);
        cJSON_AddNumberToObject(node, "noproto", ifmd.ifmd_data.ifi_noproto);
        cJSON_AddNumberToObject(node, "epoch", ifmd.ifmd_data.ifi_epoch);
        cJSON_AddNumberToObject(node, "lastchange", ifmd.ifmd_data.ifi_lastchange.tv_sec);
#if 0
        if ((ifmd.ifmd_data.ifi_type == IFT_ETHER) || (ifmd.ifmd_data.ifi_type == IFT_ISO88023)) {
                name[5] = IFDATA_LINKSPECIFIC;
                if (sysctl(name, 6, 0, &linkmiblen, 0, 0) < 0)
                        err(EX_OSERR,
                            "sysctl(net.link.ifdata.%d.linkspec) size",
                            ifnum);
                if (!linkmib)
                        err(EX_OSERR, "malloc(%lu)",
                            (u_long)linkmiblen);
                struct ifmib_iso_8802_3 *md;
                linkmiblen = sizeof(*md);
                if (sysctl(name, 6, md, &linkmiblen, 0, 0) < 0)
                        err(EX_OSERR,
                            "sysctl(net.link.ifdata.%d.linkspec)",
                            ifnum);
                if (linkmiblen == sizeof(*md)) {
                cJSON* stats = cJSON_CreateObject();
                cJSON_AddNumberToObject(stats, "alignment", md->dot3StatsAlignmentErrors);
                cJSON_AddNumberToObject(stats, "fcs", md->dot3StatsFCSErrors);
                cJSON_AddNumberToObject(stats, "single_collision", md->dot3StatsSingleCollisionFrames);
                cJSON_AddNumberToObject(stats, "multiple_collision", md->dot3StatsMultipleCollisionFrames);
                cJSON_AddNumberToObject(stats, "heartbeat_errors", md->dot3StatsSQETestErrors);
                cJSON_AddNumberToObject(stats, "deferred_transmissions", md->dot3StatsDeferredTransmissions);
                cJSON_AddNumberToObject(stats, "late_collisions", md->dot3StatsLateCollisions);
                cJSON_AddNumberToObject(stats, "excessive_collisions", md->dot3StatsExcessiveCollisions);
                cJSON_AddNumberToObject(stats, "internal_transmit_errors", md->dot3StatsInternalMacTransmitErrors);
                cJSON_AddNumberToObject(stats, "carrier_sense_errors", md->dot3StatsCarrierSenseErrors);
                cJSON_AddNumberToObject(stats, "frame_too_long", md->dot3StatsFrameTooLongs);
                cJSON_AddNumberToObject(stats, "internal_receive_errors", md->dot3StatsInternalMacReceiveErrors);
                cJSON_AddNumberToObject(stats, "missed_frames", md->dot3StatsMissedFrames);
                cJSON_AddItemToObject(node, "mac", stats);
                }
        }                                
#endif        
        
                

}



//struct ifmibdata {
//        char    ifmd_name[IFNAMSIZ]; /* name of interface */
//        int     ifmd_pcount;    /* number of promiscuous listeners */
//        int     ifmd_flags;     /* interface flags */
//        int     ifmd_snd_len;   /* instantaneous length of send queue */
//        int     ifmd_snd_maxlen; /* maximum length of send queue */
//        int     ifmd_snd_drops; /* number of drops in send queue */
//        int     ifmd_filler[4]; /* for future expansion */
//        struct  if_data ifmd_data; /* generic information and statistics */
//};


static const char *
iftype(int type)
{
        static char buf[256];

        if (type <= 0 || type >= NIFTYPES) {
                sprintf(buf, "unknown type %d", type);
                return buf;
        }

        return if_types[type];
}

static const char *
iftyped(int type)
{
        static char buf[256];

        if (type <= 0 || type >= NIFTYPESD) {
                sprintf(buf, "unknown type %d", type);
                return buf;
        }

        return if_typesd[type];
}

cJSON * testandset(int value, int test) {
        if (value & test)
                return cJSON_CreateTrue();
        return cJSON_CreateFalse();
}

cJSON * ifflags(uint64_t flags) {

        cJSON * l = cJSON_CreateObject();
        cJSON_AddBoolToObject(l, "up", flags & IFF_UP);
        cJSON_AddBoolToObject(l, "broadcast", flags & IFF_BROADCAST);
        cJSON_AddBoolToObject(l, "debug", flags & IFF_DEBUG);
        cJSON_AddBoolToObject(l, "loopback", flags & IFF_LOOPBACK);
        cJSON_AddBoolToObject(l, "pointtopoint", flags & IFF_POINTOPOINT);
#ifdef IFF_SMART
        cJSON_AddBoolToObject(l, "smart", flags & IFF_SMART);
#endif
        cJSON_AddBoolToObject(l, "running", flags & IFF_RUNNING);
        cJSON_AddBoolToObject(l, "noarp", flags & IFF_NOARP);
        cJSON_AddBoolToObject(l, "promisc", flags & IFF_PROMISC);
        cJSON_AddBoolToObject(l, "allmulti", flags & IFF_ALLMULTI);
        cJSON_AddBoolToObject(l, "oactive", flags & IFF_DRV_OACTIVE);
        cJSON_AddBoolToObject(l, "simplex", flags & IFF_SIMPLEX);
        cJSON_AddBoolToObject(l, "link0", flags & IFF_LINK0);
        cJSON_AddBoolToObject(l, "link1", flags & IFF_LINK1);
        cJSON_AddBoolToObject(l, "link2", flags & IFF_LINK2);
        cJSON_AddBoolToObject(l, "multicast", flags & IFF_MULTICAST);
        cJSON_AddBoolToObject(l, "cantconfig", flags & IFF_CANTCONFIG);
        cJSON_AddBoolToObject(l, "ppromisc", flags & IFF_PPROMISC);
        cJSON_AddBoolToObject(l, "monitor", flags & IFF_MONITOR);
        cJSON_AddBoolToObject(l, "staticarp", flags & IFF_STATICARP);
        cJSON_AddBoolToObject(l, "dying", flags & IFF_DYING);
        cJSON_AddBoolToObject(l, "renaming", flags & IFF_RENAMING);
        
        return l;
}

cJSON * ifhwcaps(uint64_t flags) {

        cJSON * l = cJSON_CreateObject();
        cJSON_AddBoolToObject(l, "rxcsum", flags & IFCAP_RXCSUM);
        cJSON_AddBoolToObject(l, "txcsum", flags & IFCAP_TXCSUM);
        cJSON_AddBoolToObject(l, "netcons", flags & IFCAP_NETCONS);
        cJSON_AddBoolToObject(l, "vlan_mtu", flags & IFCAP_VLAN_MTU);
        cJSON_AddBoolToObject(l, "vlan_hwtagging", flags & IFCAP_VLAN_HWTAGGING);
        cJSON_AddBoolToObject(l, "jumbo_mtu", flags & IFCAP_JUMBO_MTU);
        cJSON_AddBoolToObject(l, "polling", flags & IFCAP_POLLING);
        cJSON_AddBoolToObject(l, "vlan_hwcsum", flags & IFCAP_VLAN_HWCSUM);
        cJSON_AddBoolToObject(l, "tso4", flags & IFCAP_TSO4);
        cJSON_AddBoolToObject(l, "tso6", flags & IFCAP_TSO6);
        cJSON_AddBoolToObject(l, "lro", flags & IFCAP_LRO);
        cJSON_AddBoolToObject(l, "wol_ucast", flags & IFCAP_WOL_UCAST);
        cJSON_AddBoolToObject(l, "wol_mcast", flags & IFCAP_WOL_MCAST);
        cJSON_AddBoolToObject(l, "wol_magic", flags & IFCAP_WOL_MAGIC);
        cJSON_AddBoolToObject(l, "toe4", flags & IFCAP_TOE4);
        cJSON_AddBoolToObject(l, "toe6", flags & IFCAP_TOE6);
        cJSON_AddBoolToObject(l, "vlan_hwfilter", flags & IFCAP_VLAN_HWFILTER);
        cJSON_AddBoolToObject(l, "polling_nocount", flags & IFCAP_POLLING_NOCOUNT);
        cJSON_AddBoolToObject(l, "vlan_hwtso", flags & IFCAP_VLAN_HWTSO);
        cJSON_AddBoolToObject(l, "linkstate", (flags & IFCAP_LINKSTATE) ? 1:0);
        cJSON_AddBoolToObject(l, "netmap", flags & IFCAP_NETMAP);
        cJSON_AddBoolToObject(l, "rxcsum_ipv6", flags & IFCAP_RXCSUM_IPV6);
        cJSON_AddBoolToObject(l, "txcsum_ipv6", flags & IFCAP_TXCSUM_IPV6);
        cJSON_AddBoolToObject(l, "hwstats", flags & IFCAP_HWSTATS);
        cJSON_AddBoolToObject(l, "hwcsum", flags & IFCAP_HWCSUM);
        cJSON_AddBoolToObject(l, "tso", flags & IFCAP_TSO);
        cJSON_AddBoolToObject(l, "wol", flags & IFCAP_WOL);
        cJSON_AddBoolToObject(l, "toe", (flags & IFCAP_TOE) ? 1 : 0);
        
        return l;
}
