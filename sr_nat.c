
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_protocol.h"

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  nat->next_port = 1024;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));


  /* free nat memory here */
  struct sr_nat_mapping *walker = nat->mappings;
	while (walker != NULL) {
		struct sr_nat_mapping *temp = walker;
		walker = walker->next;
		free(temp);
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  struct sr_nat_mapping *walker;

  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    walker = nat->mappings;
    while (walker){
      if (walker->type == nat_mapping_icmp){
        sr_nat_clean_icmp(nat, walker, curtime);
      } else if (walker->type == nat_mapping_tcp){
        sr_nat_clean_tcp(nat, walker, curtime);
      }
      walker = walker->next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

void sr_nat_clean_icmp(struct sr_nat *nat, struct sr_nat_mapping *icmp_mapping, time_t curtime){

  if ((curtime - icmp_mapping->last_updated) > nat->timeout_icmp){
    struct sr_nat_mapping *prev_mapping = 0;
    struct sr_nat_mapping *mapping =sr_get_original_mapping(nat, icmp_mapping, &prev_mapping);

    if (prev_mapping) {
      prev_mapping-> next = mapping->next;
    } else {
      nat->mappings = mapping-> next;
    }
    free(mapping);
  }
}

void sr_nat_clean_tcp(struct sr_nat *nat, struct sr_nat_mapping *tcp_mapping, time_t curtime){

  struct sr_nat_connection *conn = tcp_mapping->conns;
  struct sr_nat_connection *prev_conn = 0;



  while (conn){

    if ( (conn->established && ((curtime - conn->last_updated) > nat->timeout_tcp_est)) ||
         (!conn->syn_sent &&((curtime - conn->last_updated) > nat->timeout_tcp_trans))){
      struct sr_nat_mapping *prev_mapping = 0;
      struct sr_nat_mapping *mapping = sr_get_original_mapping(nat, tcp_mapping, &prev_mapping);
      sr_close_connection(nat, conn, prev_conn, mapping, prev_mapping);


    }
    prev_conn = conn;
    conn = conn->next;
  }
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *walker = nat->mappings;

  while (walker != NULL) {
		if (walker->aux_ext == aux_ext && walker->type == type) {
			walker->last_updated = time(NULL);
			copy = malloc(sizeof(struct sr_nat_mapping));
			memcpy(copy, walker, sizeof(struct sr_nat_mapping));
			break;
		}
		walker = walker->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *walker = nat->mappings;

	while (walker != NULL) {
		if (walker->ip_int == ip_int && walker->aux_int == aux_int
        && walker->type == type) {
			walker->last_updated = time(NULL);
			copy = malloc(sizeof(struct sr_nat_mapping));
			memcpy(copy, walker, sizeof(struct sr_nat_mapping));
			break;
		}
		walker = walker->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */

  struct sr_if *ext_iface = sr_get_interface(nat->sr, "eth2");
  struct sr_nat_mapping *mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));

  mapping->type = type;
	mapping->ip_int = ip_int;
	mapping->ip_ext = ext_iface->ip;
	mapping->aux_int = aux_int;
  mapping->aux_ext = htons(nat->next_port);
	mapping->last_updated = time(NULL);
  mapping->conns = NULL;

  /* Increment next_port which needs to be between 1024 and 65535 */
  if (nat->next_port < 65535) {
    nat->next_port = nat->next_port + 1;
  } else {
    nat->next_port = 1024;
  }

  /* Insert mapping to the head of the mappings list */
	mapping->next = nat->mappings;
	nat->mappings = mapping;

  /* Create a copy for returning */
	struct sr_nat_mapping *mapping_copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  memcpy(mapping_copy, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return mapping_copy;
}

/* NAT recieves packet from router for translating */
int sr_nat_handle_packet(struct sr_instance* sr, uint8_t *packet,
    unsigned int len, char* interface) {
  struct sr_ip_hdr *ip_pckt = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));

  int internal_src = check_if_ip_inside_nat(sr, ip_pckt->ip_src);
  int internal_dst = check_if_ip_inside_nat(sr, ip_pckt->ip_dst);
  struct sr_if* eth2_if = sr_get_interface(sr, "eth2");

  switch(ip_pckt->ip_p) {
    case ip_protocol_icmp:
      if (internal_src && !internal_dst) {
        /* outgoing ICMP packet */
        return sr_nat_translate_icmp_out(sr, packet, len, interface);
      } else if (!internal_src && (ip_pckt->ip_dst == eth2_if->ip)) {
        /* incoming ICMP packet */
        return sr_nat_translate_icmp_in(sr, packet, len, interface);
      }
    	break;


    case ip_protocol_tcp:

      if (internal_src && !internal_dst) {
        /* outgoing TCP packet */
        return sr_nat_translate_tcp_out(sr, packet, len, interface);
      } else if ((!internal_src && (ip_pckt->ip_dst == eth2_if->ip)) || (internal_src && internal_dst)) {
        /* incoming TCP packet */
        return sr_nat_translate_tcp_in(sr, packet, len, interface);
      }
      break;
  }

  return 1; /* unsuported protocol: protocol not IP or TCP */
}

/* Translate incoming TCP pckt */
int sr_nat_translate_tcp_in(struct sr_instance* sr, uint8_t *packet,
    unsigned int len, char* interface) {

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));



  pthread_mutex_lock(&(sr->nat->lock));
  struct sr_nat_mapping *mapping = sr_nat_lookup_external(sr->nat, tcp_hdr->tcp_dport, nat_mapping_tcp);
  if (!mapping){

    struct sr_rt *rt = sr_get_matching_rt(sr, ip_hdr->ip_src);
    struct sr_if *out_if = sr_get_interface(sr, rt->interface);

    /* SYN sent from internal host. Send ICMP unreachable */
    if (check_if_ip_inside_nat(sr, ip_hdr->ip_src)){

      sr_send_icmp_pkt(sr, eth_hdr, ip_hdr, out_if, icmp_unreachable, 3);
      return 0;
    }
    if ((ntohs(tcp_hdr->tcp_dport)) < 1024){

      sr_send_icmp_pkt(sr, eth_hdr, ip_hdr, out_if, icmp_unreachable, 3);
      return 0;
    }
    if ((ntohs(tcp_hdr->tcp_dport)) >= 1024){

      sleep(6);
      sr_send_icmp_pkt(sr, eth_hdr, ip_hdr, out_if, icmp_unreachable, 3);
      return 0;
    }
  }
  else {

    ip_hdr->ip_dst = mapping->ip_int;
    tcp_hdr->tcp_dport = mapping->aux_int;

    tcp_hdr->tcp_sum = 0;
    tcp_hdr->tcp_sum = cksum(tcp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    free(mapping);
  }
  pthread_mutex_unlock(&(sr->nat->lock));
  return 0;
}

/* Update TCP connection for incoming packet */
void sr_nat_update_tcp_in_conn(struct sr_instance *sr, uint8_t *packet,
    struct sr_nat_mapping *mapping) {


  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  struct sr_nat *nat = sr->nat;

  uint32_t ip_adr = ip_hdr->ip_src;
  uint16_t port_num = tcp_hdr->tcp_sport;

  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping *prev_mapping;
  mapping = sr_get_original_mapping(nat, mapping, &prev_mapping);

  struct sr_nat_connection *prev_conn = NULL;
  struct sr_nat_connection *conn = sr_get_connection(mapping, ip_adr, port_num, &prev_conn);

  /* Save FIN sequence */
  if (tcp_hdr->tcp_flags & TCP_FIN) {
    conn->fin_rec_seq = ntohl(tcp_hdr->tcp_seq);
  }

  /* SYN sent but received SYN only, instead of SYN + ACK  */
  conn->syn_received = conn->syn_received ||
      (conn->syn_sent && (tcp_hdr->tcp_flags & TCP_SYN) && !(tcp_hdr->tcp_flags & TCP_ACK));

  /* ACK for termination request received  */
  conn->fin_wait_2 = conn->fin_wait_2 ||
      (conn->fin_wait_1 && (tcp_hdr->tcp_flags & TCP_ACK));

  pthread_mutex_unlock(&(nat->lock));
}

/* returns tcp_hdr from packet */
sr_tcp_hdr_t *get_tcp_header(uint8_t *packet){
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  return tcp_hdr;
}

/* returns ip_hdr from packet */
sr_ip_hdr_t *get_ip_header(uint8_t *packet){
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  return ip_hdr;
}

/* Translate outbound TCP pckt */
int sr_nat_translate_tcp_out(struct sr_instance* sr, uint8_t *packet,
    unsigned int len, char* interface) {

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  uint16_t port = tcp_hdr->tcp_sport;
  struct sr_nat_mapping *mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, port, nat_mapping_tcp);
  if (!mapping) {

    mapping = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, port, nat_mapping_tcp);

  }



  ip_hdr->ip_src = mapping->ip_ext;
  tcp_hdr->tcp_sport = mapping->aux_ext;

  tcp_hdr->tcp_sum = 0;
  tcp_hdr->tcp_sum = cksum(tcp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

  ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  free(mapping);
  return 0;
}

/* Update TCP connection for outgoing packet */
void sr_nat_update_tcp_out_conn(struct sr_instance *sr, uint8_t *packet,
  struct sr_nat_mapping *mapping) {

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  struct sr_nat *nat = sr->nat;

  uint32_t ip_adr = ip_hdr->ip_dst;
  uint16_t port_num = tcp_hdr->tcp_dport;

  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping *prev_mapping;
  mapping = sr_get_original_mapping(nat, mapping, &prev_mapping);
  if (!mapping) {
    return; /* original mapping not found */
  }

  struct sr_nat_connection *prev_conn = NULL;
  struct sr_nat_connection *conn = sr_get_connection(mapping, ip_adr, port_num, &prev_conn);

  /* Sync with TCP header flags */
  if (tcp_hdr->tcp_flags & TCP_FIN) {
    conn->fin_sent_seq = ntohl(tcp_hdr->tcp_seq);
  }

  /* Third leg of 3-way-handshake will set conn->established  */
  if ((conn->established = conn->syn_sent && (tcp_hdr->tcp_flags & TCP_ACK))){
    conn->listen = 0;
  }

  conn->syn_sent = conn->syn_sent || (tcp_hdr->tcp_flags & TCP_SYN);
  conn->fin_wait_1 = conn->fin_wait_1 || (tcp_hdr->tcp_flags & TCP_FIN);
  conn->time_wait = conn->time_wait || (conn->fin_rec_seq < ntohl(tcp_hdr->tcp_ack));

  /* Close connection if FACK has been sent or if packet has RST flagged */
	if ((conn->time_wait) || (tcp_hdr->tcp_flags & TCP_RST)) {
    sr_close_connection(nat, conn, prev_conn, mapping, prev_mapping);
  }
  pthread_mutex_unlock(&(nat->lock));
}

/* Get pointer to original mapping that matches our copy of it */
struct sr_nat_mapping *sr_get_original_mapping(struct sr_nat *nat,
      struct sr_nat_mapping *copy, struct sr_nat_mapping **prev_mapping) {

  struct sr_nat_mapping *curr = nat->mappings;
  while (curr) {
    if ((curr->type == copy->type) && (curr->ip_int == copy->ip_int)
        && (curr->aux_int ==  copy->aux_int)) {
      return curr;
    }
    *prev_mapping = curr;
    curr = curr->next;
  }
  return NULL;
}

/* Get connection for this mapping that matches the given ip and port.
If no match exists, create a new connection. */
struct sr_nat_connection *sr_get_connection(struct sr_nat_mapping *mapping,
    uint32_t ip_adr, uint16_t port_num, struct sr_nat_connection **prev_conn) {

  struct sr_nat_connection *conn = mapping->conns;
  while (conn) {
    if (conn->ip_ext == ip_adr && conn->port_ext == port_num) {
      conn->last_updated = time(NULL);
      return conn;
    }
    *prev_conn = conn;
    conn = conn->next;
  }

  return sr_new_connection(mapping, ip_adr, port_num);
}

/* Create new connection with the given ip and port for the given mapping. */
struct sr_nat_connection *sr_new_connection(struct sr_nat_mapping *mapping,
    uint32_t ip_adr, uint16_t port_num) {
  struct sr_nat_connection *conn = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
  conn->last_updated = time(NULL);
  conn->ip_ext = ip_adr;
  conn->port_ext = port_num;
  conn->fin_sent_seq = 0;
  conn->fin_rec_seq = 0;
  conn->established = 0;
  conn->syn_sent=0;
  conn->syn_received=0;
  conn->established=0;
  conn->fin_wait_1=0;
  conn->fin_wait_2=0;
  conn->time_wait=0;
  conn->listen=0;


  conn->next = mapping->conns;
  mapping->conns = conn;
  return conn;
}

/* Close a TCP connetion */
void sr_close_connection(struct sr_nat *nat, struct sr_nat_connection *conn,
      struct sr_nat_connection *prev_conn, struct sr_nat_mapping *mapping,
      struct sr_nat_mapping *prev_mapping) {
  /* Remove this connection from mapping's list of connections */
  if (prev_conn) {
    prev_conn->next = conn->next;
  } else {
    mapping->conns = conn->next;
  }
  free(conn);

  /* Free mapping if no more TCP connections */
  if (!(mapping->conns)) {
    if (prev_mapping) {
      prev_mapping-> next = mapping->next;
    } else {
      nat->mappings = mapping-> next;
    }
    free(mapping);
  }
}

/* Translate incoming ICMP packet */
int sr_nat_translate_icmp_in(struct sr_instance* sr, uint8_t *packet,
    unsigned int len, char* interface) {

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint16_t port = icmp_hdr->identifier;

  struct sr_nat_mapping *mapping = sr_nat_lookup_external(sr->nat, port, nat_mapping_icmp);

  if (mapping) {
    ip_hdr->ip_dst = mapping->ip_int;
    icmp_hdr->identifier = mapping->aux_int;

    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    ip_hdr->ip_sum = 0;
	  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
	  free(mapping);
  }


  return 0;
}

/* Translate outgoing ICMP packet */
int sr_nat_translate_icmp_out(struct sr_instance* sr, uint8_t *packet,
    unsigned int len, char* interface) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint16_t port = icmp_hdr->identifier;


  struct sr_nat_mapping *mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, port, nat_mapping_icmp);

  if (!mapping) {
    mapping = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, port, nat_mapping_icmp);
  }

  if (mapping) {
    ip_hdr->ip_src = mapping->ip_ext;
    icmp_hdr->identifier = mapping->aux_ext;

    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    ip_hdr->ip_sum = 0;
	  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
	  free(mapping);
  }


  return 0;
}

/* Check if an ip address is within the nat */
int check_if_ip_inside_nat(struct sr_instance *sr, uint32_t ip) {
	struct sr_rt *match = sr_get_matching_rt(sr, ip);
	return(match && (strncmp(match->interface, "eth1", 4) == 0));
}
