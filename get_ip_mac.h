#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

void get_mac(char* dev, char* mymac) {
  int fd;
  struct ifreq ifr;
  char* mac;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy((char*)ifr.ifr_name, (const char*)dev, IFNAMSIZ - 1);

  ioctl(fd, SIOCGIFHWADDR, &ifr);
  close(fd);

  mac = (char*)ifr.ifr_hwaddr.sa_data;
  sprintf((char*)mymac, (const char*)"%02x:%02x:%02x:%02x:%02x:%02x",
          mac[0] & 0xff, mac[1] & 0xff, mac[2] & 0xff, mac[3] & 0xff,
          mac[4] & 0xff, mac[5] & 0xff);
}

void get_ip(char* iface_name, char* ip_buffer){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ -1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    sprintf(ip_buffer, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}
