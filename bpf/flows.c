#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>

#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "flow.h"

#define DISCARD 1
#define SUBMIT 0

// according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define INGRESS 0
#define EGRESS 1

#define TRANSMIT_MODE      00
#define RECIEVE_MODE       01

#define SERVICE_FORWARD    8
#define SERVICE_TCP_SPLIT  12
#define SERVICE_ENCRYPTION 16

#define EI_PORT            5001
#define FORWARD_PORT       5100
#define TCP_SPLIT_PORT     5200
#define ENCRYPTION_PORT    5300

// TODO: for performance reasons, replace the ring buffer by a hashmap and
// aggregate the flows here instead of the Go Accounter
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} flows SEC(".maps");

// Constant definitions, to be overridden by the invoker
volatile const u32 service_mode = 0;

const u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

// sets flow fields from IPv4 header information
static inline int fill_iphdr(struct iphdr *ip, void *data_end, struct flow *flow) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    __builtin_memcpy(flow->network.src_ip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(flow->network.dst_ip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(flow->network.src_ip.s6_addr + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));
    __builtin_memcpy(flow->network.dst_ip.s6_addr + sizeof(ip4in6), &ip->daddr, sizeof(ip->daddr));
    flow->transport.protocol = ip->protocol;

    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            flow->transport.src_port = __bpf_ntohs(tcp->source);
            flow->transport.dst_port = __bpf_ntohs(tcp->dest);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            flow->transport.src_port = __bpf_ntohs(udp->source);
            flow->transport.dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}

// sets flow fields from IPv6 header information
static inline int fill_ip6hdr(struct ipv6hdr *ip, void *data_end, struct flow *flow) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    flow->network.src_ip = ip->saddr;
    flow->network.dst_ip = ip->daddr;
    flow->transport.protocol = ip->nexthdr;

    switch (ip->nexthdr) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            flow->transport.src_port = __bpf_ntohs(tcp->source);
            flow->transport.dst_port = __bpf_ntohs(tcp->dest);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            flow->transport.src_port = __bpf_ntohs(udp->source);
            flow->transport.dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}
// sets flow fields from Ethernet header information
static inline int fill_ethhdr(struct ethhdr *eth, void *data_end, struct flow *flow) {
    if ((void *)eth + sizeof(*eth) > data_end) {
        return DISCARD;
    }
    __builtin_memcpy(flow->data_link.dst_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(flow->data_link.src_mac, eth->h_source, ETH_ALEN);
    flow->protocol = __bpf_ntohs(eth->h_proto);
    // TODO: ETH_P_IPV6
    if (flow->protocol == ETH_P_IP) {
        struct iphdr *ip = (void *)eth + sizeof(*eth);
        return fill_iphdr(ip, data_end, flow);
    } else if (flow->protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
        return fill_ip6hdr(ip6, data_end, flow);
    }
    return SUBMIT;
}



static inline int add_service (struct ethhdr *eth, void *data_end) {
    u16 protocol= bpf_ntohs(eth->h_proto);
    struct iphdr *ip = (void *)eth + sizeof(*eth);

    if ((protocol == ETH_P_IP) && ((void *)ip + sizeof(*ip) <= data_end)) {
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                u8 old_tos,new_tos;
                u16 dport;
                dport = __bpf_ntohs(tcp->dest);;
                //tos update
                if (dport == EI_PORT) {
                    u16 old_csum,new_csum;
                    old_tos = ip->tos;
                    new_tos = old_tos | 0b0100;
                    ip->tos = new_tos;
                    bpf_printk("[tc] old tos=%x new tos=%x\n", old_tos, new_tos);

                    //checksum update
                    old_csum = __bpf_ntohs(ip->check);
                    new_csum= old_csum + (new_tos - old_tos);

                    new_csum = ~old_csum + (ip->tos - old_tos);
                    if (new_csum>>16) {
                        new_csum = (new_csum & 0xffff) + (new_csum >> 16);

                    }
                    new_csum=~new_csum;

                    bpf_printk("[tc] old checksum=%x new checksum=%x\n", old_csum, new_csum);
                    ip->check = __bpf_ntohs(new_csum);
                }
            }
        }
    }
    return SUBMIT;
}

static inline int route2service (struct ethhdr *eth, void *data_end) {
    u16 protocol= bpf_ntohs(eth->h_proto);
    struct iphdr *ip = (void *)eth + sizeof(*eth);

    //bpf_printk("[tc] Inside route2servcie");
       if ((protocol == ETH_P_IP) && ((void *)ip + sizeof(*ip) <= data_end)) {
        if (ip->protocol == IPPROTO_TCP) {
            u8 tos= ip->tos;
            bpf_printk("[tc] ip tos=%x ",tos);

            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                u8 tos;
                u16 old_dport,new_dport;
                u16 old_sport,new_sport;
                tos = ip->tos;
                old_dport =__bpf_ntohs(tcp->dest);
                //incoming traffic shaping
                if (old_dport == EI_PORT) {
                    switch (tos) {
                    case SERVICE_FORWARD: {
                        new_dport =FORWARD_PORT;
                        tcp->dest =__bpf_ntohs(new_dport);
                        bpf_printk("[tc] Incoming traffic: old dport=%d  new dport=%d \n", old_dport, new_dport);
                    } break;
                    default:
                        break;
                    }
                }
                //outgoing traffic shaping
                old_sport =__bpf_ntohs(tcp->source);
                if ((old_sport == FORWARD_PORT) || (old_sport == TCP_SPLIT_PORT)) {
                    new_sport =EI_PORT;
                    tcp->source =__bpf_ntohs(new_sport);
                    bpf_printk("enter tc_func inside SYN flag");
                    bpf_printk("[tc] outgoing traffic: old sport=%d new sport=%d \n", old_sport, new_sport);
                }
            }
        }
    }
    return SUBMIT;
}
// parses flow information for a given direction (ingress/egress)
static inline int flow_parse(struct __sk_buff *skb, u8 direction) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct flow *flow = bpf_ringbuf_reserve(&flows, sizeof(struct flow), 0);
    if (!flow) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
    if (fill_ethhdr(eth, data_end, flow) == DISCARD) {
        bpf_ringbuf_discard(flow, 0);
    } else {
        if (service_mode == TRANSMIT_MODE){
            add_service(eth,data_end);
        } else {
            route2service(eth,data_end);
        }
        flow->direction = direction;
        flow->bytes = skb->len;
        bpf_ringbuf_submit(flow, 0);
    }

    return TC_ACT_OK;
}

SEC("tc/ingress_flow_parse")
static inline int ingress_flow_parse(struct __sk_buff *skb) {
    return flow_parse(skb, INGRESS);
}

SEC("tc/egress_flow_parse")
static inline int egress_flow_parse(struct __sk_buff *skb) {
    return flow_parse(skb, EGRESS);
}

char __license[] SEC("license") = "GPL";
