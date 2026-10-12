#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/icmp.h>
#include <net/checksum.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Amir Emami");
MODULE_DESCRIPTION("Netfilter random payload modifier (POSTROUTING, dst=10.1.1.180)");

static struct nf_hook_ops nfho;

static unsigned int hook_func(void *priv,
                              struct sk_buff *skb,
                              const struct nf_hook_state *state)
{
    struct iphdr *iph;
    unsigned char *payload;
    unsigned int payload_len = 0;

    if (!skb)
        return NF_ACCEPT;

    if (skb_linearize(skb) != 0)
        return NF_ACCEPT;

    if (skb_try_make_writable(skb, skb->len))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    /* ONLY packets going to 10.1.1.180 */
    if (iph->daddr != htonl(0xA0101B4))
        return NF_ACCEPT;

    /* determine protocol payload */
    if (iph->protocol == IPPROTO_TCP) {

        struct tcphdr *tcph = (struct tcphdr *)((unsigned char *)iph + iph->ihl * 4);
        unsigned int ip_header_len = iph->ihl * 4;
        unsigned int tcp_header_len = tcph->doff * 4;

        if (skb->len < ip_header_len + tcp_header_len)
            return NF_ACCEPT;

        payload = (unsigned char *)tcph + tcp_header_len;
        payload_len = ntohs(iph->tot_len) - ip_header_len - tcp_header_len;

    } else if (iph->protocol == IPPROTO_UDP) {

        struct udphdr *udph = (struct udphdr *)((unsigned char *)iph + iph->ihl * 4);
        unsigned int ip_header_len = iph->ihl * 4;

        if (skb->len < ip_header_len + sizeof(struct udphdr))
            return NF_ACCEPT;

        payload = (unsigned char *)udph + sizeof(struct udphdr);
        payload_len = ntohs(udph->len) - sizeof(struct udphdr);

    } else if (iph->protocol == IPPROTO_ICMP) {

        struct icmphdr *icmph = (struct icmphdr *)((unsigned char *)iph + iph->ihl * 4);
        unsigned int ip_header_len = iph->ihl * 4;

        if (skb->len < ip_header_len + sizeof(struct icmphdr))
            return NF_ACCEPT;

        payload = (unsigned char *)icmph + sizeof(struct icmphdr);
        payload_len = ntohs(iph->tot_len) - ip_header_len - sizeof(struct icmphdr);

    } else {
        return NF_ACCEPT;
    }

    if (payload_len == 0)
        return NF_ACCEPT;

    if (payload + payload_len > skb_tail_pointer(skb))
        return NF_ACCEPT;

    /* overwrite payload with random bytes */
    get_random_bytes(payload, payload_len);

    /* recompute IP checksum */
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

    /* recalc transport checksums */
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = tcp_hdr(skb);
        unsigned int tcp_len = ntohs(iph->tot_len) - iph->ihl * 4;

        tcph->check = 0;
        tcph->check = csum_tcpudp_magic(
            iph->saddr,
            iph->daddr,
            tcp_len,
            IPPROTO_TCP,
            csum_partial((char *)tcph, tcp_len, 0)
        );

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = udp_hdr(skb);
        unsigned int udp_len = ntohs(udph->len);

        udph->check = 0;
        udph->check = csum_tcpudp_magic(
            iph->saddr,
            iph->daddr,
            udp_len,
            IPPROTO_UDP,
            csum_partial((char *)udph, udp_len, 0)
        );

        if (udph->check == 0)
            udph->check = CSUM_MANGLED_0;
    }

    return NF_ACCEPT;
}

static int __init nfmod_init(void)
{
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_POST_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);

    printk(KERN_INFO "payload_obfs: loaded (dst=10.1.1.180)\n");
    return 0;
}

static void __exit nfmod_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "payload_obfs: unloaded\n");
}

module_init(nfmod_init);
module_exit(nfmod_exit);
