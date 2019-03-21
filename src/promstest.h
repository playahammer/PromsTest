#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>  
#include <ifaddrs.h>       
#include <errno.h>
#include <unistd.h>

#define ETHNAME "ens33"

#define BUFFER_SIZE 1024

#define MALLOC(pptr, structs, size) \
      do{ \
          *pptr = (structs *)malloc(size);  \
          if((*pptr) == NULL)\
          { printf("Error: Init failed.\n"); exit(1);}\
      }while(0)
typedef struct _arp_packet
{
      u_int8_t destination[6];
      u_int8_t sender[6];
      u_int16_t type;
      u_int16_t ar_hdr;
      u_int16_t ar_pro;
      u_int8_t ar_hln;
      u_int8_t ar_pln;
      u_int16_t ar_op;
      u_int8_t *ar_sha;
      u_int8_t *ar_spa;
      u_int8_t *ar_tha;
      u_int8_t *ar_tpa;

}arp_packet;

void arp_get_locator_mac(u_int8_t **mac, u_int8_t **ip_address);

void arp_packet_create(arp_packet **pp, u_int8_t *target);

int arp_packet_byte(arp_packet *p, char ** buffer);

int promstest(u_int8_t *target);

void arp_packet_unpacked(arp_packet **data, char *buffer, int buffer_size);