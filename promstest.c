#include "promstest.h"

/***
 * 
 *  get the local protocol address and hardware address 
 * 
 */
void arp_get_locator_mac(u_int8_t **mac, u_int8_t **ip_address)
{
      MALLOC(mac, u_int8_t, sizeof(u_int8_t) * 6);
      MALLOC(ip_address, u_int8_t, sizeof(u_int8_t) * 4);
      struct sockaddr_in *addr;
      struct ifaddrs *ifadr, *if_list;

      if(getifaddrs(&if_list) < 0)
      {
            perror("Error");
            exit(1);
      }

      for(ifadr = if_list; ifadr != NULL; ifadr = ifadr->ifa_next)
      {
            if(ifadr->ifa_addr->sa_family == AF_INET)
            {
                  if(strcmp(ETHNAME, ifadr->ifa_name) == 0)
                  {
                        addr = (struct sockaddr_in *) ifadr->ifa_addr;
                        **ip_address = (addr->sin_addr.s_addr << 24) >> 24;
                        *(*ip_address + 1) = (addr->sin_addr.s_addr << 16) >> 24;
                        *(*ip_address + 2) = (addr->sin_addr.s_addr << 8) >> 24;
                        *(*ip_address + 3) = (addr->sin_addr.s_addr) >> 24;

                  }
            }

            if(ifadr->ifa_addr->sa_family == AF_PACKET)
            {
                  struct sockaddr_ll *s = (struct sockaddr_ll *)(ifadr->ifa_addr);
                  for(int i = 0; i < 6; i++)
                  {
                        *(*mac + i) = s->sll_addr[i];
                  }
            }
      }
}     

/**
 *  create arp packet
 */ 
void arp_packet_create(arp_packet **pp, u_int8_t *target)
{
    MALLOC(pp, arp_packet, sizeof(arp_packet));

    arp_packet *p = *pp;

    char dest_hd[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xfe};
    strncpy(p->destination, dest_hd, 6);
    u_int8_t *local_pd;
    u_int8_t *local_hd;
    arp_get_locator_mac(&local_hd, &local_pd);
    
    memcpy(&(p->sender), local_hd, 6);
    p->type = 0x0806;
    p->ar_hdr = 0x0001;
    p->ar_pro = 0x0800;
    p->ar_hln = 0x06;
    p->ar_pln = 0x04;
    p->ar_op = 0x0001;

    MALLOC(&(p->ar_sha), u_int8_t, p->ar_hln);
    memcpy(p->ar_sha, local_hd, p->ar_hln);
    MALLOC(&(p->ar_spa), u_int8_t, p->ar_pln);
    memcpy(p->ar_spa, local_pd, p->ar_pln);

    char dest_hd_proms[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    MALLOC(&(p->ar_tha), u_int8_t, p->ar_hln);
    memcpy(p->ar_tha, dest_hd_proms, p->ar_hln);
    MALLOC(&(p->ar_tpa), u_int8_t, p->ar_pln);
    memcpy(p->ar_tpa, target, sizeof(target));
}
/**
 *  transform the arp_packet pointer to char array
 * 
 */
int arp_packet_byte(arp_packet *p, char ** buffer)
{
    int len = (sizeof(p->sender) + 2 * sizeof(p->type) + sizeof(p->ar_pln) + p->ar_pln + p->ar_hln) * 2;

    MALLOC(buffer, char, sizeof(char) * len);

    int index = 0;

    char *buffer_p = *buffer;

    for(int i = 0; i < 6; i++)
        buffer_p[index++] = p->destination[i] & 0xff;
    
    for(int i = 0; i < 6; i++)
        buffer_p[index++] = p->sender[i] & 0xff;

    buffer_p[index++] = (p->type >> 8) & 0xff;
    buffer_p[index++] = p->type & 0xff;

    buffer_p[index++] = (p->ar_hdr >> 8) & 0xff;
    buffer_p[index++] = p->ar_hdr & 0xff;

    buffer_p[index++] = (p->ar_pro >> 8) & 0xff;
    buffer_p[index++] = p->ar_pro & 0xff;

    buffer_p[index++] = p->ar_hln;
    buffer_p[index++] = p->ar_pln;

    buffer_p[index++] = (p->ar_op >> 8) & 0xff;
    buffer_p[index++] = p->ar_op & 0xff;

    for(int i = 0; i < p->ar_hln; i++)
        buffer_p[index++] = p->ar_sha[i];
    for(int i = 0; i < p->ar_pln; i++)
        buffer_p[index++] = p->ar_spa[i];

    for(int i = 0; i < p->ar_hln; i++)
        buffer_p[index++] = p->ar_tha[i];
    for(int i = 0; i < p->ar_pln; i++)
        buffer_p[index++] = p->ar_tpa[i];

    return index;
}

/**
 * the whole logic function
 * 
 */
int promstest(u_int8_t *target)
{
    arp_packet *pp;
    arp_packet_create(&pp, target);

    char *send_buffer;
    int send_len = arp_packet_byte(pp, &send_buffer);

    int sockfd, sockld;

    if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("Error");
        return -1;
    }
      
    if((sockld = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
    {
         perror("Error");
        return -1;
    }
    struct sockaddr_ll addr_ll;
    memset(&addr_ll, 0, sizeof(addr_ll));

    addr_ll.sll_family = AF_PACKET;
    addr_ll.sll_protocol = pp->type;
    addr_ll.sll_ifindex = if_nametoindex(ETHNAME);
    memcpy(addr_ll.sll_addr, pp->destination, 6);

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;


    if(setsockopt(sockld, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        perror("Error");
        close(sockfd);
        return -1;
    }
    char recv_buffer[BUFFER_SIZE];
    memset(recv_buffer, 0,  BUFFER_SIZE);

    int recv_len;
    if(sendto(sockfd, send_buffer, send_len, 0, (struct sockaddr*) &addr_ll, sizeof(addr_ll)) < 0)
    {
        perror("Error");
        close(sockfd);
        return -1;
    }

    if((recv_len = recv(sockld, recv_buffer, BUFFER_SIZE, 0)) < 0)
    {
        close(sockfd);
        close(sockld);
        printf("Target: IP: %d.%d.%d.%d. Promiscuous mode: No.\n", pp->ar_tpa[0], pp->ar_tpa[1], pp->ar_tpa[2], pp->ar_tpa[3]);
        return -1;
    }

    arp_packet *up_ptr;
    arp_packet_unpacked(&up_ptr, recv_buffer, recv_len);

    printf("Target: IP: %d.%d.%d.%d MAC: %02x.%02x.%02x.%02x.%02x.%02x. Promiscuous mode: Yes.\n", \
        up_ptr->ar_spa[0], up_ptr->ar_spa[1], up_ptr->ar_spa[2], up_ptr->ar_spa[3], \
        up_ptr->ar_sha[0], up_ptr->ar_sha[1], up_ptr->ar_sha[2], up_ptr->ar_sha[3], up_ptr->ar_sha[4], up_ptr->ar_sha[5]); 
    
    close(sockfd);
    close(sockld);
    free(pp);
    free(up_ptr);
    return 1;
    
}

/****
 *  unpacked the arp packet from target host
 *  
 */
void arp_packet_unpacked(arp_packet **data, char *buffer, int buffer_size)
{
      MALLOC(data, arp_packet, sizeof(arp_packet));

      int index = 0;

      for(int i = 0; i < sizeof((*data)->destination); i++)
            (*data)->destination[i] = buffer[index++];

      for(int i = 0; i < sizeof((*data)->sender); i++)
            (*data)->sender[i] = buffer[index++];
            
      (*data)->type = (buffer[index] << 8) + buffer[index + 1];
      index += 2;

      (*data)->ar_hdr = (buffer[index] << 8) + buffer[index + 1];
      index += 2;

      (*data)->ar_pro = (buffer[index] << 8) + buffer[index + 1];
      index += 2;

      (*data)->ar_hln = buffer[index++];
      (*data)->ar_pln = buffer[index++];

      (*data)->ar_op = (buffer[index] << 8) + buffer[index + 1];
      index += 2;

      MALLOC(&((*data)->ar_sha), u_int8_t, sizeof(u_int8_t) * (*data)->ar_hln);

      for(int i = 0; i < (*data)->ar_hln; i++)
            (*data)->ar_sha[i] = buffer[index++];

      MALLOC(&((*data)->ar_spa), u_int8_t, sizeof(u_int8_t) * (*data)->ar_pln);

      for(int i = 0; i < (*data)->ar_pln; i++)
            (*data)->ar_spa[i] = buffer[index++];

      MALLOC(&((*data)->ar_tha), u_int8_t, sizeof(u_int8_t) * (*data)->ar_hln);

      for(int i = 0; i < (*data)->ar_hln; i++)
            (*data)->ar_tha[i] = buffer[index++];

      MALLOC(&((*data)->ar_tpa), u_int8_t, sizeof(u_int8_t) * (*data)->ar_pln);

      for(int i = 0; i < (*data)->ar_pln; i++)
            (*data)->ar_tpa[i] = buffer[index++];
}

// the application entrance

int main(int argc, char **argv)
{
    if(argc < 2)
    {
        printf("Error: Lack the ip address argument.\n");
        return 0;
    }
    char *ip = NULL;
    if((ip = argv[1]) == NULL)
    {
        printf("Error: Lack the ip address argument.\n");
        return 0;
    }
    int addr = inet_addr(ip);
    u_int8_t dest[] = {(addr << 24) >> 24, (addr << 16) >> 24, (addr << 8) >> 24, addr >> 24};
    promstest(dest);
    return 0;
}