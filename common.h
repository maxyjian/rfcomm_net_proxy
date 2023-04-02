#ifndef __COMMON_H__
#define __COMMON_H__

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <ifaddrs.h>
#include <linux/if_bridge.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <uv.h>

#define RECOMM_NET_LOG_LEVEL 0
#define RECOMM_NET_SUPPORT_DATA_PRINT 0
#define RECOMM_NET_SUPPORT_XOR_CHECK 0
#define RECOMM_NET_SUPPORT_ESCAPE_CHAR 0

#define RAW_(format, ...) syslog(4, format, ##__VA_ARGS__)
#define ERROR_(format, ...) syslog(3, "%d: " format, __LINE__, ##__VA_ARGS__)
#define WARN_(format, ...) syslog(2, "%d: " format, __LINE__, ##__VA_ARGS__)
#define INFO_(format, ...) syslog(1, "%d: " format, __LINE__, ##__VA_ARGS__)
#define DEBUG_(format, ...) syslog(0, "%d: " format, __LINE__, ##__VA_ARGS__)

/* TUN:(1518 - sizeof(ethernet_hdr_t)) TAP:1518*/
#define TAP_MAX_PKT_WRITE_LEN 1518

typedef struct {
    char* cmd;
    int (*function)(int argc, char** argv);
    char* help;
} rfcomm_net_command_t;

struct list_node {
    struct list_node* prev;
    struct list_node* next;
};

typedef int (*cmd_cb)(int argc, char* argv[]);
typedef void (*del_cb)(struct list_node* item);
typedef int (*check_cb)(struct list_node* item, int index);

void rfcomm_net_list_init(struct list_node* list);
void rfcomm_net_list_add_item(struct list_node* list, struct list_node* item);
void rfcomm_net_list_del_item(struct list_node* item, del_cb cb);
int rfcomm_net_list_traversal(struct list_node* list, check_cb cb, int index);
void rfcomm_net_list_destroy(struct list_node* list, del_cb cb);

void syslog(int level, const char* fmt, ...);
uint8_t rfcomm_net_xor_calculate(uint8_t* data, int len);
void rfcomm_net_hex_print(char* tag, uint8_t* data, int len);
void rfcomm_net_protocol_send(int fd, uint8_t* data, int len);
void rfcomm_net_protocol_receive(int fd, uint8_t* data, int len);
int rfcomm_net_get_host_bt_addr(bdaddr_t* addr);
int rfcomm_net_iface_set_mac(const char* if_name, const char* mac);
int rfcomm_net_iface_up(const char* if_name);
int rfcomm_net_iface_down(const char* if_name);
int rfcomm_net_iface_set_ip(char* ip, char* br_name);
int rfcomm_net_iface_get_state(char* net_name);
int rfcomm_net_tap_open(const char* if_name, const char* mac_addr);
void rfcomm_net_tap_close(const char* if_name, int tap_fd);
int rfcomm_net_command_start(uv_loop_t* loop, cmd_cb cb);
int rfcomm_net_command_stop(void);
void rfcomm_net_uv_poll_stop(uv_poll_t* handle);
uv_poll_t* rfcomm_net_uv_poll_start(uv_loop_t* loop, int fd, int pevents,
    uv_poll_cb cb, void* userdata);

#endif
