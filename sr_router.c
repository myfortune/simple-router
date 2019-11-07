/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet, len);

  /* fill in code here */
  struct sr_if *i = sr_get_interface(sr, interface);
  uint16_t type = ethertype(packet);

  if (type == ethertype_ip) {
    /* Translate packet if nat is enabled. Drop pckt if failed to translate */
    if (sr->nat_enabled) {
      fprintf(stderr, "Got IP packet and NAT is enabled.\n");
      if (sr_nat_handle_packet(sr, packet, len, interface)) {
        return; /* Packet was not translated so drop it */
      }
    } else {
      fprintf(stderr, "nat not enabled.\n");
    }
    sr_handle_ip_pckt(sr, packet, len, i);
  } else if (type == ethertype_arp) {
    sr_handle_arp_pckt(sr, packet, len, i);
  } else {
    fprintf(stderr, "Packet does not have type IP or ARP\n");
  }


}/* end sr_ForwardPacket */

/* Handle ARP request and reply packets */
void sr_handle_arp_pckt(struct sr_instance *sr, uint8_t *packet,
        unsigned int len, struct sr_if *interface) {

  struct sr_ethernet_hdr *ether_hdr = (struct sr_ethernet_hdr *)(packet);
  struct sr_arp_hdr *arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Packet is an ARP request */
  if (ntohs(arp_hdr->ar_op) == arp_op_request) {

    /* Send reply to this request if target ip matches interface ip */
    if(arp_hdr->ar_tip == interface->ip) {
      sr_send_arp_reply(sr, ether_hdr, arp_hdr, interface);
    }

  /* Packet is an ARP reply */
  } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {

    /* Handle ARP reply if target ip matches interface ip */
    if(arp_hdr->ar_tip == interface->ip) {

      /* Add reply to cache and get the request with this ip */
      struct sr_arpreq *request = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

      /* If request exists, loop through the packets waiting on this request */
      if (request) {
        struct sr_packet *curr_pckt = request->packets;
          while (curr_pckt) {
            /* Get the ethernet header and then copy over the MAC address as the
               destination and the interface address as the source before sending packet */
            struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *)(curr_pckt->buf);
            memcpy(e_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            memcpy(e_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr, curr_pckt->buf, curr_pckt->len, interface->name);

            curr_pckt = curr_pckt->next;
          }

          /* Destroy the request */
          sr_arpreq_destroy(&(sr->cache), request);
      }
    }
  }
}

struct sr_arpreq *sr_find_request(struct sr_arpreq *request, uint32_t ip){
  while(request) {
    if (request->ip == ip) {
      return request;
    }
    request = request->next;
  }
  return NULL;
}

/* Handle IP packets */
void sr_handle_ip_pckt(struct sr_instance *sr, uint8_t *packet,
        unsigned int len, struct sr_if *interface) {

  struct sr_ethernet_hdr *ether_hdr = (struct sr_ethernet_hdr *)packet;
  struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Verify checksum and length of packet */
  if (!sr_verify_checksum(ip_hdr) || !sr_verify_length(len)) {
    fprintf(stderr, "Checksum / length invalid. Dropping ip packet. \n");
    return;
  }

  /* Check if packet is destined for one of the router's ip addresses
    by looping through the router's interfaces. */
  struct sr_if *curr_iface = sr->if_list;
  while (curr_iface) {
    if (curr_iface->ip == ip_hdr->ip_dst) {
      sr_handle_destined_ip(sr, packet, len, curr_iface);
      return;
    }

    curr_iface = curr_iface->next;
  }

  /* Packet not destined for one of our interfaces. Go through routing table
     to find entry with longest prefix match with the destination ip address */
  struct sr_rt *rt = sr_get_matching_rt(sr, ip_hdr->ip_dst);
  if (rt) {
    /* Entry found. Get the interface to foward the packet on and then forward packet */
    struct sr_if *out_iface = sr_get_interface(sr, rt->interface);
    sr_forward_ip_pckt(sr, packet, len, out_iface);
  }
  else {
    /* No matching entry in rtable. Send destination net unreachable ICMP packet */
    sr_send_icmp_pkt(sr, ether_hdr, ip_hdr, interface, icmp_unreachable, 0);
  }
}

/* Returns 1 if checksum for ip_hdr is valid. Otherwise returns 0 */
int sr_verify_checksum(sr_ip_hdr_t *ip_hdr) {
  uint16_t sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;

  if(cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != sum) {
    ip_hdr->ip_sum = sum;
    return 0;
  } else {
    ip_hdr->ip_sum = sum;
    return 1;
  }
}

/* Returns 1 if length of packet is valid. Otherwise returns 0 */
int sr_verify_length(unsigned int len) {
  if (len >= (sizeof(sr_ethernet_hdr_t) +
      sizeof(sr_ip_hdr_t))) {
    return 1;
  }
  return 0;
}

/* Handle IP packet destined to one of the router's interfaces */
void sr_handle_destined_ip(struct sr_instance *sr, uint8_t *packet,
      unsigned int len, struct sr_if *iface) {

  struct sr_ethernet_hdr *ether_hdr = (struct sr_ethernet_hdr *)(packet);
  struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_icmp_hdr *icmp_hdr;

  switch (ip_protocol((uint8_t *) ip_hdr)){

    case ip_protocol_icmp:
      /* Send echo reply if type is echo request */
      icmp_hdr = (struct sr_icmp_hdr *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      if (icmp_hdr->icmp_type == icmp_echo_request){
        sr_send_icmp_echo(sr, packet, iface, icmp_echo_request, 0, len);
      }
      break;
    case ip_protocol_udp: /* falls through and move to the next case */
    case ip_protocol_tcp:
      /* Send port unreachable for type TCP */
      sr_send_icmp_pkt(sr, ether_hdr, ip_hdr, iface, icmp_unreachable, 3);
      break;
  }
}

/* Send modified ICMP echo request packet back out as an echo reply */
void sr_send_icmp_echo(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface,
    int icmp_type, int icmp_code, unsigned int len){

  struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)(packet);
  struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_icmp_hdr *icmp_hdr = (struct sr_icmp_hdr *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* Get interface for sending packet */
  struct sr_rt *rt = sr_get_matching_rt(sr, ip_hdr->ip_src);
  struct sr_if *out_if = sr_get_interface(sr, rt->interface);

  /* Modify ethernet header */
  memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);

  /* Modify IP header */
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = interface->ip;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  /* Modify ICMP header */
  icmp_hdr->icmp_type = icmp_echo_reply;
  icmp_hdr->icmp_code = 0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

  /* Get Mac address from arpque entry or queue packet */
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);

  if (arp_entry){ /* Assign MAC address to the ether header */
    memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

    /* Send the packet */
    sr_send_packet(sr, packet, len, out_if->name);
    free(arp_entry);

  } else { /* Add request to queue and send the arp request */
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet,
        len, out_if->name);
    sr_handle_arpreq(req, sr, out_if);
  }

}

/* Send ARP reply packet */
void sr_send_arp_reply(struct sr_instance *sr, struct sr_ethernet_hdr *ether_hdr,
    struct sr_arp_hdr *arp_hdr, struct sr_if *interface) {

  /* Allocate space for the packet */
  unsigned int pckt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *pckt = (uint8_t *)malloc(pckt_len);

  /* Set ethernet header */
  struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *)pckt;
  memcpy(e_hdr->ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(e_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
  e_hdr->ether_type = htons(ethertype_arp);

  /* Set ARP header */
  struct sr_arp_hdr *new_arp_hdr = (struct sr_arp_hdr *)(pckt + sizeof(sr_ethernet_hdr_t));
  sr_set_arp_hdr(new_arp_hdr, arp_op_reply, interface->addr,
      interface->ip, arp_hdr->ar_sha, arp_hdr->ar_sip);

  sr_send_packet(sr, pckt, pckt_len, interface->name);
}

/* Forward IP packet */
void sr_forward_ip_pckt(struct sr_instance *sr, uint8_t *packet,
        unsigned int len, struct sr_if *interface) {

  struct sr_ethernet_hdr *ether_hdr = (struct sr_ethernet_hdr *)packet;
  struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Decrement TTL. If TTL now equals zero, drop packet. Otherwise, recompute checksum */
  ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
  if(ip_hdr->ip_ttl <= 0) {
    /* Send Time Exceeded ICMP msg */
    sr_send_icmp_pkt(sr, ether_hdr, ip_hdr, interface, icmp_time_exceeded, 0);
    return;
  }
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  /* Try to get MAC address from cache. If sucessful, send the ip packet */
  struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
  if (entry) {
    memcpy(ether_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

    sr_send_packet(sr, packet, len, interface->name);
    free(entry);
  }

  /* Add request to queue and send the arp request */
  else {
    struct sr_arpreq *request = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet,
        len, interface->name);
    sr_handle_arpreq(request, sr, interface);
  }
}

/* Send ICMP unreachable and time exceeded packets (type 3 and 11) */
void sr_send_icmp_pkt(struct sr_instance *sr, struct sr_ethernet_hdr *ether_hdr,
  struct sr_ip_hdr *origin_ip_hdr, struct sr_if *interface, int icmp_type, int icmp_code){

  /* Allocate space for the packet */
  unsigned int pckt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  if (icmp_type == icmp_unreachable){
    pckt_len += sizeof(sr_icmp_t3_hdr_t);
  } else if (icmp_type == icmp_time_exceeded){
    pckt_len += sizeof(sr_icmp_t11_hdr_t);
  }

  uint8_t *pckt = (uint8_t *)malloc(pckt_len);

  /* Get interface for sending packet */
  struct sr_rt *rt = sr_get_matching_rt(sr, origin_ip_hdr->ip_src);
  struct sr_if *out_if = sr_get_interface(sr, rt->interface);

  /* Set Ethernet header. Destination/Source address is to be assigned after setting other headers */
  struct sr_ethernet_hdr *new_ether_hdr = (struct sr_ethernet_hdr *)pckt;
  memcpy(new_ether_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
  new_ether_hdr->ether_type = htons(ethertype_ip);

  /* Set IP header */
  struct sr_ip_hdr *new_ip_hdr = (struct sr_ip_hdr *)(pckt + sizeof(sr_ethernet_hdr_t));
  new_ip_hdr->ip_hl = origin_ip_hdr->ip_hl;
  new_ip_hdr->ip_id = origin_ip_hdr->ip_id;
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_tos = origin_ip_hdr->ip_tos;
  new_ip_hdr->ip_off = htons(IP_DF);
  new_ip_hdr->ip_ttl = INIT_TTL;
  new_ip_hdr->ip_v = origin_ip_hdr->ip_v;
  new_ip_hdr->ip_src = interface->ip;
  new_ip_hdr->ip_dst = origin_ip_hdr->ip_src;
  new_ip_hdr->ip_len = htons(pckt_len - sizeof(sr_ethernet_hdr_t));
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

  /* Declare ICMP headers of different types */
  struct sr_icmp_t3_hdr *new_icmp_t3_hdr;
  struct sr_icmp_t11_hdr *new_icmp_t11_hdr;

  switch (icmp_type) {

    /* Set header for ICMP Type 3 Unreachable Packet */
    case icmp_unreachable:
      new_icmp_t3_hdr = (struct sr_icmp_t3_hdr *)(pckt + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
      new_icmp_t3_hdr->icmp_type = icmp_unreachable;
      new_icmp_t3_hdr->icmp_code = icmp_code;
      new_icmp_t3_hdr->unused = 0;
      new_icmp_t3_hdr->next_mtu = 0;
      memcpy(new_icmp_t3_hdr->data, origin_ip_hdr, ICMP_DATA_SIZE);
      new_icmp_t3_hdr->icmp_sum = 0;
      new_icmp_t3_hdr->icmp_sum = cksum(new_icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
      break;

    /* Set header for ICMP Time Exceeded Type 11 Packet */
    case icmp_time_exceeded:
      new_icmp_t11_hdr = (struct sr_icmp_t11_hdr *)(pckt + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
      new_icmp_t11_hdr->icmp_type = icmp_time_exceeded;
      new_icmp_t11_hdr->icmp_code = 0;
      new_icmp_t11_hdr->unused = 0;
      memcpy(new_icmp_t11_hdr->data, origin_ip_hdr, ICMP_DATA_SIZE);
      new_icmp_t11_hdr->icmp_sum = 0;
      new_icmp_t11_hdr->icmp_sum = cksum(new_icmp_t11_hdr, sizeof(sr_icmp_t11_hdr_t));
      break;
  }

  /* Get Mac address from arpque entry or queue packet */
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), origin_ip_hdr->ip_src );
  if (arp_entry){ /* Assign MAC address to the ether header and send the packet */
    memcpy(new_ether_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, pckt, pckt_len, out_if->name);
    free(arp_entry);

  } else {/* Add request to queue and send the arp request */
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), origin_ip_hdr->ip_src, pckt,
        pckt_len, out_if->name);

    sr_handle_arpreq(req, sr, out_if);
  }
}
