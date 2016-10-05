#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/tcp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander Prichman");
MODULE_DESCRIPTION("Module closes port 9999");



unsigned int close_port(void *priv,
			struct sk_buff *skb,
			const struct nf_hook_state *state);



struct nf_hook_ops nfops;

int init_module(void)
{
	nfops.hook = close_port;
	nfops.pf = PF_INET;
	nfops.hooknum = NF_INET_LOCAL_IN;
	nfops.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfops);

	printk(KERN_INFO "cls_port module: init.\n");
	return 0;
}

void cleanup_module(void)
{
	nf_unregister_hook(&nfops);
	printk(KERN_ALERT "cls_port module: closed.\n");
}



unsigned int close_port(void *priv,
			struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	struct iphdr *ip_hdr;
	struct tcphdr *tcp_hdr;

	if (skb->protocol == htons(ETH_P_IP)) {
		ip_hdr = (struct iphdr *)skb_network_header(skb);
		if (ip_hdr->version == 4 &&
		    ip_hdr->protocol == IPPROTO_TCP) {
			/* Задаем смещение в байтах для указателя на TCP заголовок */
			/* ip->ihl - длина IP заголовка в 32-битных словах */
			skb_set_transport_header(skb, ip_hdr->ihl * 4);
			/* Сохраняем указатель на структуру заголовка TCP */
			tcp_hdr = (struct tcphdr *)skb_transport_header(skb);
			printk(KERN_INFO "cls_port: d_port=%hu\n", tcp_hdr->dest);
			if (tcp_hdr->dest == 9999) {
				printk(KERN_INFO "cls_port: packet found!\n");
				return NF_DROP;
			}
		}
	}

	return NF_ACCEPT;
}
