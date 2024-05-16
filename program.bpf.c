// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

#ifndef PACKET_HOST
#define PACKET_HOST 0
#endif

#ifndef PACKET_OUTGOING
#define PACKET_OUTGOING 4
#endif

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800 /* Internet Protocol packet     */
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef AF_INET
#define AF_INET 2 /* Internet IP Protocol 	*/
#endif

#ifndef AF_INET6
#define AF_INET6 10 /* IP version 6                 */
#endif

// See include/net/ipv6.h
#ifndef NEXTHDR_NONE
#define NEXTHDR_HOP 0       /* Hop-by-hop option header. */
#define NEXTHDR_TCP 6       /* TCP segment. */
#define NEXTHDR_UDP 17      /* UDP message. */
#define NEXTHDR_ROUTING 43  /* Routing header. */
#define NEXTHDR_FRAGMENT 44 /* Fragmentation/reassembly header. */
#define NEXTHDR_AUTH 51     /* Authentication header. */
#define NEXTHDR_NONE 59     /* No next header */
#define NEXTHDR_DEST 60     /* Destination options header. */
#endif

#define IP_HLEN 20
#define UDP_HLEN 8
#define DNS_OFF (ETH_HLEN + IP_HLEN + UDP_HLEN)

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
union dnsflags {
  struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 rcode : 4;  // response code
    __u8 z : 3;      // reserved
    __u8 ra : 1;     // recursion available
    __u8 rd : 1;     // recursion desired
    __u8 tc : 1;     // truncation
    __u8 aa : 1;     // authoritive answer
    __u8 opcode : 4; // kind of query
    __u8 qr : 1;     // 0=query; 1=response
#elif __BYTE_ORDER == __ORDER_BIG_ENDIAN__
    __u8 qr : 1;     // 0=query; 1=response
    __u8 opcode : 4; // kind of query
    __u8 aa : 1;     // authoritive answer
    __u8 tc : 1;     // truncation
    __u8 rd : 1;     // recursion desired
    __u8 ra : 1;     // recursion available
    __u8 z : 3;      // reserved
    __u8 rcode : 4;  // response code
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif
  };
  __u16 flags;
};

struct dnshdr {
  __u16 id;

  union dnsflags flags;

  __u16 qdcount; // number of question entries
  __u16 ancount; // number of answer entries
  __u16 nscount; // number of authority records
  __u16 arcount; // number of additional records
};

// DNS resource record
// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
#pragma pack(push, 2)
struct dnsrr {
  __u16 name; // Two octets when using message compression, see
              // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
  __u16 type;
  __u16 class;
  __u32 ttl;
  __u16 rdlength;
  // Followed by rdata
};
#pragma pack(pop)

enum op {
  getaddrinfo,
  gethostbyname,
  gethostbyname2,
  networkpacket,
};

// Max DNS name length: 255
// https://datatracker.ietf.org/doc/html/rfc1034#section-3.1
#define MAX_DNS_NAME 255

struct event {
  gadget_mntns_id mntns_id;
  __u32 pid;
  __u32 tid;
  char comm[TASK_COMM_LEN];
  enum op operation;
  char name[MAX_DNS_NAME];
  char service[MAX_DNS_NAME];
  struct gadget_l3endpoint_t endpoint;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(udns, events, event);

// struct addrinfo comes from netdb.h in glibc or musl:
// https://sourceware.org/git/?p=glibc.git;a=blob;f=resolv/netdb.h;hb=ded2e0753e9c46debeb2e0d26c5e560d2581d314#l565
// https://git.etalabs.net/cgit/musl/tree/include/netdb.h#n16
struct addrinfo {
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  __u32 ai_addrlen;
  struct sockaddr *ai_addr;
  char *ai_canonname;
  struct addrinfo *ai_next;
};

struct lookup {
  const char *node;
  const char *service;
  const void *hints;
  const struct addrinfo **res;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u32); // tid
  __type(value, struct lookup);
} lookups SEC(".maps");

SEC("uprobe/libc:getaddrinfo")
int BPF_UPROBE(getaddrinfo_e, const char *node, const char *service,
               const void *hints, const struct addrinfo **res) {
  u64 mntns_id;
  u64 pid_tgid;
  u32 tid;
  struct lookup lookup = {};

  mntns_id = gadget_get_mntns_id();
  if (gadget_should_discard_mntns_id(mntns_id))
    return 0;

  pid_tgid = bpf_get_current_pid_tgid();
  tid = (__u32)pid_tgid;

  lookup.node = node;
  lookup.service = service;
  lookup.hints = hints;
  lookup.res = res;

  bpf_map_update_elem(&lookups, &tid, &lookup, BPF_ANY);

  return 0;
}

SEC("uretprobe/libc:getaddrinfo")
int BPF_URETPROBE(getaddrinfo_x, int ret) {
  struct event *event;
  u64 mntns_id;
  u64 pid_tgid;
  u32 pid, tid;
  struct lookup *lookup;
  struct addrinfo *result;
  int ai_family;
  struct sockaddr_in *addr;

  mntns_id = gadget_get_mntns_id();
  if (gadget_should_discard_mntns_id(mntns_id))
    return 0;

  pid_tgid = bpf_get_current_pid_tgid();
  pid = pid_tgid >> 32;
  tid = (__u32)pid_tgid;

  lookup = bpf_map_lookup_elem(&lookups, &tid);
  if (!lookup)
    return 0;

  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  event->mntns_id = mntns_id;
  event->pid = pid;
  event->tid = tid;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  event->operation = getaddrinfo;
  bpf_probe_read_user_str(event->name, sizeof(event->name), lookup->node);
  bpf_probe_read_user_str(event->service, sizeof(event->service),
                          lookup->service);

  bpf_probe_read_user(&result, sizeof(result), lookup->res);
  bpf_probe_read_user(&ai_family, sizeof(ai_family), &result->ai_family);
  if (ai_family == AF_INET) {
    event->endpoint.version = 4;
    bpf_probe_read_user(&addr, sizeof(addr), &result->ai_addr);
    bpf_probe_read_user(&event->endpoint.addr.v4,
                        sizeof(event->endpoint.addr.v4), &addr->sin_addr);
  } else if (ai_family == AF_INET6) {
    event->endpoint.version = 6;
    bpf_probe_read_user(&addr, sizeof(addr), &result->ai_addr);
    bpf_probe_read_user(&event->endpoint.addr.v6,
                        sizeof(event->endpoint.addr.v6), &addr->sin_addr);
  } else {
    gadget_discard_buf(event);
    return 0;
  }

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  return 0;
}

static __always_inline __u32 dns_name_length(struct __sk_buff *skb) {
  long err;
  // This loop iterates over the DNS labels to find the total DNS name
  // length.
  unsigned int i;
  unsigned int skip = 0;
  for (i = 0; i < MAX_DNS_NAME; i++) {
    if (skip != 0) {
      skip--;
    } else {
      __u8 label_len;
      err = bpf_skb_load_bytes(skb, DNS_OFF + sizeof(struct dnshdr) + i,
                               &label_len, sizeof(label_len));
      if (err < 0 || label_len == 0)
        break;
      // The simple solution "i += label_len" gives verifier
      // errors, so work around with skip.
      skip = label_len;
    }
  }

  return i < MAX_DNS_NAME ? i : MAX_DNS_NAME;
}

SEC("socket1")
int ig_trace_dns(struct __sk_buff *skb) {
  struct event *event;
  long err;
  struct lookup *lookup;
  u32 tid = 0;

  // Skip non-IP packets
  __u16 h_proto;
  err = bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto,
                           sizeof(h_proto));
  if (err < 0 || h_proto != bpf_htons(ETH_P_IP))
    return 0;

  // Skip non-UDP packets
  __u8 proto;
  err = bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol),
                           &proto, sizeof(proto));
  if (err < 0 || proto != IPPROTO_UDP)
    return 0;

  union dnsflags flags;
  err = bpf_skb_load_bytes(skb, DNS_OFF + offsetof(struct dnshdr, flags),
                           &flags.flags, sizeof(flags.flags));
  if (err < 0)
    return 0;
  // struct dnsflags has different definitions depending on __BYTE_ORDER__
  // but the two definitions are reversed field by field and not bytes so
  // we need an extra ntohs().
  flags.flags = bpf_ntohs(flags.flags);

  // Skip DNS packets with more than 1 question
  __u16 qdcount;
  err = bpf_skb_load_bytes(skb, DNS_OFF + offsetof(struct dnshdr, qdcount),
                           &qdcount, sizeof(qdcount));
  if (err < 0)
    return 0;
  qdcount = bpf_ntohs(qdcount);
  if (qdcount != 1)
    return 0;

  // Skip DNS queries with answers
  __u16 ancount, nscount;
  err = bpf_skb_load_bytes(skb, DNS_OFF + offsetof(struct dnshdr, ancount),
                           &ancount, sizeof(ancount));
  if (err < 0)
    return 0;
  ancount = bpf_ntohs(ancount);
  err = bpf_skb_load_bytes(skb, DNS_OFF + offsetof(struct dnshdr, nscount),
                           &nscount, sizeof(nscount));
  if (err < 0)
    return 0;
  nscount = bpf_ntohs(nscount);

  if (flags.qr == 0 && ancount + nscount != 0)
    return 0;

  __u32 name_len = dns_name_length(skb);
  if (name_len == 0)
    return 0;

  struct sockets_value *skb_val = gadget_socket_lookup(skb);
  if (skb_val)
    tid = (__u32)skb_val->pid_tgid;

  if (tid) {
    lookup = bpf_map_lookup_elem(&lookups, &tid);
    if (lookup)
      return 0;
  }

  // Emit event
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  bpf_skb_load_bytes(skb, DNS_OFF + sizeof(struct dnshdr), event->name,
                     name_len);

  // Skip mdns
  if (event->name[1] == '_') {
    gadget_discard_buf(event);
    return 0;
  }

  unsigned int i;
  unsigned int left = 0;
  unsigned int next = 0;
  for (i = 0; i < MAX_DNS_NAME - 1; i++) {
    if (left == 0) {
      left = event->name[i + next];
      next = 1;
      if (i > 0) {
        if (left == 0) {
          event->name[i] = '\0';
          break;
        }
        event->name[i] = '.';
        continue;
      }
    }
    event->name[i] = event->name[i + 1];
    left--;
  }

  event->endpoint.version = 4;
  event->endpoint.addr.v4 = 0x0100007F;
  event->operation = networkpacket;

  // Enrich event with process metadata
  if (skb_val != NULL) {
    event->mntns_id = skb_val->mntns;
    event->pid = skb_val->pid_tgid >> 32;
    event->tid = (__u32)skb_val->pid_tgid;
    __builtin_memcpy(&event->comm, skb_val->task, sizeof(event->comm));
    // event->uid = (__u32)skb_val->uid_gid;
    // event->gid = (__u32)(skb_val->uid_gid >> 32);
  }

  gadget_submit_buf(skb, &events, event, sizeof(*event));

  return 0;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
