#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

// For communication with the kernel
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>


// argv Position Definitions
#define FW_PROG_NAME	0
#define FW_ACTION	1
#define FW_PROTOCOL	2

#define FW_ALLOW	1
#define FW_DENY		2

#define FW_ANY		0

#define FW_MAX_PAYLOAD	1024	/* Max payload size, in bytes */
#define FW_NETLINK_ID	0

// Protocols
#define FW_ICMP		1
#define FW_TCP		6
#define FW_UDP		17

// Errors
#define FW_ERR_INVALID_PORT	-1

struct fw_ipcfg {
	int addr;
	int mask;
	int port;
};

struct fw_filter {
	struct fw_ipcfg dst;
	struct fw_ipcfg src;
	int proto;
	int action;
};


void kernel()
{
	struct sockaddr_nl snl, dnl;	
	struct nlmsghdr *hdr = NULL;
	struct iovec iov;
	struct msghdr msg;
	int sock_fd;

	sock_fd = socket(AF_NETLINK, SOCK_RAW, FW_NETLINK_ID);
	if (sock_fd < 0) {
		perror("socket");
		return;
	}

	memset(&snl, 0, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = getpid();

	bind(sock_fd, (struct sockaddr*)&snl, sizeof(struct sockaddr_nl));

	memset(&dnl, 0, sizeof(struct sockaddr_nl));
	dnl.nl_family = AF_NETLINK;
	dnl.nl_pid = 0;		/* 0: Send to Linux Kernel */
	dnl.nl_groups = 0;	/* 0: Unicast */
	
	hdr = (struct nlmsghdr*)malloc(NLMSG_SPACE(FW_MAX_PAYLOAD));
	memset(hdr, 0, NLMSG_SPACE(FW_MAX_PAYLOAD));
	hdr->nlmsg_len = NLMSG_SPACE(FW_MAX_PAYLOAD);
	hdr->nlmsg_pid = getpid();
	hdr->nlmsg_flags = 0;	

	strcpy(NLMSG_DATA(hdr), "Hello from Userspace!");

	iov.iov_base = (void*)hdr;
	iov.iov_len = hdr->nlmsg_len;
	msg.msg_name = (void*)&dnl;
	msg.msg_namelen = sizeof(dnl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf("Sending message to kernel\n");
	sendmsg(sock_fd, &msg, 0);
	printf("Waiting for message from kernel\n");
	recvmsg(sock_fd, &msg, 0);
	printf("Received message: %s\n", NLMSG_DATA(hdr));

	close(sock_fd);

}

char * get_protocol_string(int proto)
{
	switch (proto) {
	case FW_ANY:
		return "Any";
	case FW_ICMP:
		return "ICMP";
	case FW_TCP:
		return "TCP";
	case FW_UDP:
		return "UDP";
	default:
		return "Unknown";
	}
}

void print_filter(struct fw_filter *filter)
{
	char *action = (filter->action == FW_ALLOW) ? "Allow": "Deny";
	char *proto = get_protocol_string(filter->proto);

	char src_addr[INET_ADDRSTRLEN];	
	char dst_addr[INET_ADDRSTRLEN];	

	if (filter->src.addr == FW_ANY) {
		src_addr[0] = 'A'; src_addr[1] = 'n'; src_addr[2] = 'y'; src_addr[3] = '\0';
	} else {
		inet_ntop(AF_INET, &(filter->src.addr), src_addr, INET_ADDRSTRLEN);
	}

	if (filter->dst.addr == FW_ANY) {
		dst_addr[0] = 'A'; dst_addr[1] = 'n'; dst_addr[2] = 'y'; dst_addr[3] = '\0';
	} else {
		inet_ntop(AF_INET, &(filter->dst.addr), dst_addr, INET_ADDRSTRLEN);
	}
	
	printf("%s %s from %s to %s\n", action, proto, src_addr, dst_addr);
}

// Returns number of tokens consumed
int parse_ipcfg(struct fw_ipcfg *cfg, char **args, int argc)
{
	// Fill default values to begin
	cfg->addr = FW_ANY;
	cfg->mask = -1;
	cfg->port = FW_ANY;

	if (argc < 1) return 0;

	if (strncmp(args[0], "any", 3) == 0) {
		// Allow any IP
		inet_pton(AF_INET, "0.0.0.0", &(cfg->addr));
	} else {
		// Parse specific IP
		inet_pton(AF_INET, args[0], &(cfg->addr));
	}

	if ((argc < 2) || (strncmp(args[1], "from", 4) == 0) || (strncmp(args[1], "to", 2) == 0)) {
		return 1;
	}

	// We have a port number, extract it
	int port = atoi(args[1]);
	if (port == 0) {
		return FW_ERR_INVALID_PORT;
	}
	cfg->port = port;

	return 2;	
}

int compile(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "usage: %s <allow|deny> <protocol|any> to <ip|any> [port] from <ip|any> [port]\n", argv[FW_PROG_NAME]);
		return 1;
	}

	struct fw_filter filter;

	// Parse Action
	if (strncmp(argv[FW_ACTION], "allow", 5) == 0) {
		filter.action = FW_ALLOW;
	} else if (strncmp(argv[FW_ACTION], "deny", 4) == 0) {
		filter.action = FW_DENY;
	} else {
		fprintf(stderr, "%s: Invalid Action %s\n", argv[FW_PROG_NAME], argv[FW_ACTION]);
		return 1;
	}

	// Parse Protocol
	char *proto = argv[FW_PROTOCOL];
	if (strncmp(proto, "tcp", 3) == 0) {
		filter.proto = FW_TCP;
	} else if (strncmp(proto, "udp", 3) == 0) {
		filter.proto = FW_UDP;
	} else if (strncmp(proto, "icmp", 4) == 0) {
		filter.proto = FW_ICMP;
	} else if (strncmp(proto, "any", 3) == 0) {
		// Any protocol	
		filter.proto = FW_ANY;
	} else {
		// Check if it's a number (aka we don't know the protocol)
		int proto = atoi(argv[FW_PROTOCOL]);
		if (proto == 0) {
			fprintf(stderr, "%s: Unknown/Unmapped protocol '%s'. Try entering the protocol number instead\n", argv[FW_PROG_NAME], argv[FW_PROTOCOL]);
			return 1;
		}
		filter.proto = proto;  
	}

	// While the next token isn't 'to' or 'from', parse protocol options
	int argpos;
	for (argpos = FW_PROTOCOL + 1; (argpos < argc) && (strncmp(argv[argpos], "to", 2) != 0) && (strncmp(argv[argpos], "from", 4) != 0); argpos++) {
		// For now, we don't support non-standard options
	}

	// Parse IP Address and Port, separating CIDR address
	if (strncmp(argv[argpos], "to", 2) == 0) {
		++argpos; // Get next arg
		int opts_parsed = parse_ipcfg(&(filter.dst), argv + argpos, argc - argpos);
		if (opts_parsed == FW_ERR_INVALID_PORT) {
			fprintf(stderr, "%s: Only supports port numbers, not names for ports...(yet)\n", argv[FW_PROG_NAME]);
			return -1;
		}
		++argpos; // Get next arg
		parse_ipcfg(&(filter.src), argv + argpos + opts_parsed, argc - argpos - opts_parsed);

	} else if (strncmp(argv[argpos], "from", 4) == 0) {
		++argpos;
		int opts_parsed = parse_ipcfg(&(filter.src), argv + argpos, argc - argpos);
		if (opts_parsed == FW_ERR_INVALID_PORT) {
			fprintf(stderr, "%s: Only supports port numbers, not names for ports...(yet)\n", argv[FW_PROG_NAME]);
			return -1;
		}
		++argpos;
		parse_ipcfg(&(filter.dst), argv + argpos + opts_parsed, argc - argpos - opts_parsed);
	}

	print_filter(&filter);

	return 0;
}

int main(int argc, char **argv)
{
	kernel();

	return 0;
}
