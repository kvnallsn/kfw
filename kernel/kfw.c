#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/types.h>

#include <net/genetlink.h>

// Protocol definitions
#define FW_ANY		0
#define FW_NOMATCH	1

// Rule Types
#define FW_INPUT_RULE	0
#define FW_OUTPUT_RULE	1

// Arbitrary filter limit
#define MAX_FILTERS	50

#define FW_NETLINK_ID	0

struct fw_policy {
	__u32 from;	// Source Address
	__u32 to;	// Destination Address
	__u32 from_mask;// Subnet mask of source address
	__u32 to_mask;	// Subnet mask of destination address
	__u8 proto;	// Protocol (TCP. UDP, ICMP)
	__u16 port;	// Port to use (TCP/UDP)
	int action;	// ALLOW, DENY, DROP
};

/**
 * Simple struct to represent the start of
 * both a TCP packet and a UDP packet
 */
struct transhdr {
	__be16 src;	// Source Port
	__be16 dst;	// Destination Port
};

static struct nf_hook_ops in_nfho;			// Struct holding set of hook function options
static struct nf_hook_ops out_nfho;			// Struct holding set of hook function options
static struct fw_policy in_filters[MAX_FILTERS]; 	// Array of input filters
static struct fw_policy out_filters[MAX_FILTERS]; 	// Array of output filters
static int in_filter_count;				// Number of input filters installed
static int out_filter_count;				// Number of output filters installed

static struct sock *nl_sk = NULL;

/**
 * Receive a message over the netlink socket
 */
static void kfw_nl_recv_msg(struct sk_buff *skb)
{

	struct nlmsghdr *hdr;
	int pid, msg_size, res;
	struct sk_buff *skb_out;
	char msg[] = "Hello, from the kernel!\n";

	msg_size = strlen(msg);
	hdr = (struct nlmsghdr*)skb->data;

	printk(KERN_INFO "Netlink Received Message: %s\n", (char*)nlmsg_data(hdr));

	pid = hdr->nlmsg_pid;	/* PID of sending process */

	skb_out = nlmsg_new(msg_size, 0);
	if (!skb_out) {
		printk(KERN_ERR "Failed to allocate new skb\n");
	}

	hdr = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0; 	/* Not an multicast group */
	strncpy(nlmsg_data(hdr), msg, msg_size);

	res = nlmsg_unicast(nl_sk, skb_out, pid);

	if (res < 0) {
		printk(KERN_INFO "Error while sending back to user\n");
	}
}

/**
 * Checks to see if these IPs (Dst + Src) match the filter
 *
 * \param[in]  filter		Fitler to match against
 * \param[in]  hdr		IP Header to match with
 *
 * \return     1 on Success, 0 otherwise
 */
int ip_match(struct fw_policy *filter, struct iphdr *hdr)
{
	// Compute the masked address, as that's all we really care about
	__be32 masked_src = hdr->saddr & filter->from_mask;
	__be32 masked_dst = hdr->daddr & filter->to_mask;

	// Continue processing this filter under the following conditions:
	//   + Source IP matches AND (destination IP matches OR is set to any)
	//   + Dest IP matches AND (source IP matches OR is set to any)
	//   + Source AND Dest are both set to any
	if (((masked_src == filter->from) &&
	    ((filter->to = FW_ANY) || (masked_dst == filter->to))) ||
	    ((filter->to == masked_dst) &&
	    ((filter->from == FW_ANY) || (masked_src == filter->from))) ||
	    ((filter->from == FW_ANY) && (filter->to == FW_ANY))) {
		return 1;	
	}

	return 0;
}

/**
 * Apply a filter to a received packet buffer.  If no match is found,
 * return FW_NOMATCH, otherwise the action is returned.
 *
 * \param[in]  sock_buff	Buffer containing the packet to filter
 * \param[in]  filter		Filter to attempt to match on
 *
 * \return     FW_NOMATCH when sock_buff does not match filter, action otherwise
 */
int apply_filter(struct sk_buff *sock_buff, struct fw_policy *filter)
{
	struct iphdr *ip_header;
	struct transhdr *trans_header;

	// Extract the IP header from the buffer
	ip_header = (struct iphdr*)skb_network_header(sock_buff);

	// If the IPs match, continue
	if (ip_match(filter, ip_header)) {

		// If we don't care about the protocol, just perform the action
		if (filter->proto == FW_ANY) {
			return filter->action;
		} else if (filter->proto != ip_header->protocol) {
			// No match on the filter, return
			return FW_NOMATCH;
		}

		// If the protocl matches, process the packet
		if (filter->proto == IPPROTO_ICMP) {
			return filter->action;
		} else if ((filter->proto == IPPROTO_TCP) | (filter->proto == IPPROTO_UDP)) {
			trans_header = (struct transhdr*)skb_transport_header(sock_buff);

			if ((filter->port == trans_header->src) ||
			    (filter->port == trans_header->dst)) {
				return filter->action;
			}
		}
	}

	return FW_NOMATCH;
}


/**
 * Called when a packet is entering the device, on the input hook
 */
unsigned int input_hook(const struct nf_hook_ops *ops, struct sk_buff *skb, 
	const struct net_device *in, const struct net_device *out, 
	int (*okfn)(struct sk_buff *))
{
	int pol_id;
	// Loop through each of the input filters, until a match
	// is found, or we run out of filters
	for (pol_id = 0; pol_id < in_filter_count; pol_id++) {
		struct fw_policy *pol = &(in_filters[pol_id]);
		int val = apply_filter(skb, pol);
		if (val == FW_NOMATCH)
			continue;

		return val;
	}


	return NF_ACCEPT;

}

/**
 * Called when a packet is leaving the device, on the output hook
 */
unsigned int output_hook(const struct nf_hook_ops *ops, struct sk_buff *skb, 
	const struct net_device *in, const struct net_device *out, 
	int (*okfn)(struct sk_buff *))
{
	int pol_id;
	// Loop through each of the output filters, until a match
	// is found, or we run out of filters
	for (pol_id = 0; pol_id < out_filter_count; pol_id++) {
		struct fw_policy *pol = &(out_filters[pol_id]);
		int val = apply_filter(skb, pol);
		if (val == FW_NOMATCH)
			continue;

		return val;
	}

	return NF_ACCEPT;
}

/**
 * Compile a fitler that has been parsed in already.  To filter on any IP
 * Address, pass NULL to either from or to. If both are null, any IP is filtered. 
 * To filter on any protocol or port, pass FW_ANY to the appropriate field
 *
 * \param[in]  type	FW_INPUT_RULE to be processed on the input hook
 *                      FW_OUTPUT_RULE to be processed on the output hook
 * \param[in]  from	Source IP Address (in dotted quad, "X.X.X.X")
 * \param[in]  to	Destination IP Address (in dotted quad, "X.X.X.X")
 * \param[in]  proto	Protocol to filter on
 * \param[in]  port	Port to filter on, if applicable
 * \param[in]  action	What action to perfom, if a match is found
 */
void compile_filter(int type,
	char *from, char *to, int proto, int port, int action)
{
	struct fw_policy *filter = NULL;
	char from_addr[17], to_addr[17];
	char *slash;
	int to_cidr = 32, from_cidr = 32, i;

	if (type == FW_INPUT_RULE) {
		filter = &(in_filters[in_filter_count++]);
		//printk(KERN_INFO "Compiled: From %s Proto %d Port %d\n", from, proto, port);
	} else {
		filter = &(out_filters[out_filter_count++]);
		//printk(KERN_INFO "Compiled: To %s Proto %d Port %d\n", to, proto, port);
	}

	// Analyze from address
	if (from != NULL) {
		slash = strchr(from, '/');
		if (slash != NULL) {
			// Determine the size of the network
			// Ex. 192.168.1.0/24
			kstrtoint(slash + 1, 10, &from_cidr);
			strncpy(from_addr, from, (slash - from));
			filter->from = in_aton(from_addr);
		} else {
			filter->from = in_aton(from);
		}
	} else {
		filter->from = FW_ANY;
	}

	if (to != NULL) {
		slash = strchr(to, '/');
		if (slash != NULL) {
			kstrtoint(slash + 1, 10, &to_cidr);
			strncpy(to_addr, to, (slash - to));
			filter->to = in_aton(to_addr);
		} else {
			filter->to = in_aton(to);
		}
	} else {
		filter->to = FW_ANY;
	}

	for (i = 0; i < from_cidr; i++) {
		filter->from_mask = filter->from_mask | (1 << i);
	}

	for (i = 0; i < to_cidr; i++) {
		filter->to_mask = filter->to_mask | (1 << i);
	}

	filter->from = (filter->from & filter->from_mask);
	filter->to = (filter->to & filter->to_mask);
	filter->proto = proto;
	filter->port = htons(port);
	filter->action = action;

	printk(KERN_INFO "Compiled: %s Proto %d Port %d From %s/%d To %s/%d\n",
		(action == NF_DROP) ? "DROP" : "ALLOW", proto, port,
		(filter->from == FW_ANY) ? "Any" : from, from_cidr,
		(filter->to == FW_ANY) ? "Any" : to, to_cidr);
}

static struct netlink_kernel_cfg cfg = {
	.input = kfw_nl_recv_msg,
};

/**
 * Initialize the module
 */
static int __init start_kfw(void)
{
	in_filter_count = 0;
	out_filter_count = 0;

	// Input filters
	/*
	compile_filter(FW_INPUT_RULE, "10.0.2.5", NULL, IPPROTO_TCP, 23, NF_DROP);
	compile_filter(FW_INPUT_RULE, "10.0.2.5", NULL, IPPROTO_TCP, 22, NF_DROP);
	compile_filter(FW_INPUT_RULE, "10.0.2.5", NULL, IPPROTO_TCP, 80, NF_DROP);
	compile_filter(FW_INPUT_RULE, "10.0.2.5", NULL, IPPROTO_ICMP, 0, NF_DROP);
	compile_filter(FW_INPUT_RULE, "10.0.2.5", NULL, IPPROTO_UDP, 53, NF_ACCEPT);

	// Output Filters
	compile_filter(FW_OUTPUT_RULE, NULL, "10.0.2.5", IPPROTO_ICMP, 0, NF_DROP);
	compile_filter(FW_OUTPUT_RULE, NULL, "10.0.2.5", IPPROTO_TCP, 23, NF_DROP);
	compile_filter(FW_OUTPUT_RULE, NULL, "128.230.171.184", IPPROTO_TCP, 80, NF_DROP);
	compile_filter(FW_OUTPUT_RULE, NULL, NULL, IPPROTO_TCP, 23, NF_DROP);
	compile_filter(FW_OUTPUT_RULE, NULL, "173.252.120.6", IPPROTO_TCP, 80, NF_DROP);
	compile_filter(FW_OUTPUT_RULE, NULL, NULL, IPPROTO_TCP, 3128, NF_DROP);
	*/

	//compile_filter(FW_OUTPUT_RULE, NULL, "10.0.2.5", IPPROTO_ICMP, FW_ANY, NF_DROP);
	compile_filter(FW_OUTPUT_RULE, NULL, "10.0.2.0/24", IPPROTO_ICMP, FW_ANY, NF_DROP);
	//compile_filter(FW_OUTPUT_RULE, NULL, NULL, IPPROTO_TCP, 80, NF_DROP);

	printk(KERN_INFO "Number of Input filters: %d\n", in_filter_count);
	printk(KERN_INFO "Number of Output filters: %d\n", out_filter_count);

	// Set up the input hook
	in_nfho.hook = input_hook;
	in_nfho.hooknum = NF_INET_LOCAL_IN;
	in_nfho.pf = PF_INET;
	in_nfho.priority = NF_IP_PRI_FIRST;

	// Set up the output hook
	out_nfho.hook = output_hook;
	out_nfho.hooknum = NF_INET_LOCAL_OUT;
	out_nfho.pf = PF_INET;
	out_nfho.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&in_nfho);
	nf_register_hook(&out_nfho);


	nl_sk = netlink_kernel_create(&init_net, FW_NETLINK_ID, &cfg);

	printk(KERN_INFO "Installed Simple Firewall\n");
	return 0;
}

static void __exit stop_kfw(void)
{
	// Remove the registered hooks, cleanup data
	nf_unregister_hook(&in_nfho);
	nf_unregister_hook(&out_nfho);
	netlink_kernel_release(nl_sk);
	printk(KERN_INFO "Removed Simple Firewall\n");
}

module_init(start_kfw);
module_exit(stop_kfw);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kevin Allison <kvnallsn@gmail.com>");
MODULE_DESCRIPTION("A Simple Firewall");
