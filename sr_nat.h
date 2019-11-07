
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#include "sr_router.h"

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp,
  nat_mapping_unsolicited
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  time_t last_updated;
  uint32_t ip_ext; /* external ip */
  uint16_t port_ext; /* external port number */
  uint32_t fin_sent_seq; /* internal fin sequence number */
  uint32_t fin_rec_seq; /* external fin sequence number */




  uint8_t closed;
  uint8_t listen;


  uint8_t syn_sent;
  uint8_t syn_received;
  uint8_t established;
  uint8_t fin_wait_1;
  uint8_t fin_wait_2;
  uint8_t time_wait;


  uint8_t close_wait;
  uint8_t last_ack;
  uint8_t closing;



  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  int next_port; /* next unused port number */
  struct sr_instance *sr;
  struct sr_nat_mapping *mappings;
  unsigned int timeout_icmp;
  unsigned int timeout_tcp_est;
  unsigned int timeout_tcp_trans;
  struct sr_nat_unsolicited *unsolicited_map;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timeout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

int sr_nat_handle_packet(struct sr_instance* sr, uint8_t *packet,
    unsigned int len, char* interface);
int check_if_ip_inside_nat(struct sr_instance *sr, uint32_t ip);

/* ICMP translation */
int sr_nat_translate_icmp_out(struct sr_instance* sr, uint8_t *packet,
    unsigned int len, char* interface);
int sr_nat_translate_icmp_in(struct sr_instance* sr, uint8_t *packet,
    unsigned int len, char* interface);

/* TCP translation */
int sr_nat_translate_tcp_out(struct sr_instance* sr, uint8_t *packet,
    unsigned int len, char* interface);
int sr_nat_translate_tcp_in(struct sr_instance* sr, uint8_t *packet,
    unsigned int len, char* interface);
struct sr_nat_mapping *sr_get_original_mapping(struct sr_nat *nat,
      struct sr_nat_mapping *copy, struct sr_nat_mapping **prev_mapping);

/* TCP connections */
void sr_nat_update_tcp_in_conn(struct sr_instance *sr, uint8_t *packet,
    struct sr_nat_mapping *mapping);
void sr_nat_update_tcp_out_conn(struct sr_instance *sr, uint8_t *packet,
    struct sr_nat_mapping *mapping);
struct sr_nat_connection *sr_get_connection(struct sr_nat_mapping *mapping,
    uint32_t ip_adr, uint16_t port_num, struct sr_nat_connection **prev_conn);
struct sr_nat_connection *sr_new_connection(struct sr_nat_mapping *mapping,
    uint32_t ip_adr, uint16_t port_num);
void sr_close_connection(struct sr_nat *nat, struct sr_nat_connection *conn,
      struct sr_nat_connection *prev_conn, struct sr_nat_mapping *mapping,
      struct sr_nat_mapping *prev_mapping);

void sr_nat_clean_icmp(struct sr_nat *nat, struct sr_nat_mapping *icmp_mapping, time_t curtime);
void sr_nat_clean_tcp(struct sr_nat *nat, struct sr_nat_mapping *tcp_mapping, time_t curtime);
sr_tcp_hdr_t *get_tcp_header(uint8_t *packet);
sr_ip_hdr_t *get_ip_header(uint8_t *packet);
#endif
