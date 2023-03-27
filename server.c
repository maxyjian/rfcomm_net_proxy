#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <uv.h>

#define TAP_MAX_PKT_WRITE_LEN  (1518 - sizeof(ethernet_hdr_t))
#define TAP_IFNAME             "bt-net"
#define BR_IFNAME              "bt-bridge"
#define GATEWAY_ADDR           "192.168.10.1"
#define RFCOMM_CHANNEL         1
#define RFCOMM_NET_SERVER_UUID 0x1101

typedef struct {
    int     tun_fd;
    char    tun_devname[16];
    uint8_t peer_addr[6];

    int        rfcomm_fd;
    int        client_fd;
    uv_poll_t* tun_poll_handle;
    uv_poll_t* spp_poll_handle;
    uv_pipe_t  stdin_pipe;

    uv_loop_t* loop;
} rfcomm_net_global_t;

typedef uint8_t mac_address[6];

typedef struct ethernet_hdr {
    mac_address h_dest;
    mac_address h_src;
    short       h_proto;
} ethernet_hdr_t;

typedef struct sdp_service {
    sdp_session_t* session;
    sdp_record_t*  rec;
} sdp_service_t;

typedef struct {
    char* cmd;
    int (*function)(int argc, char** argv);
    char* help;
} rfcomm_net_command_t;

static sdp_service_t       g_sdp_service;
static rfcomm_net_global_t g_rfcomm_net;
static uint8_t             tun_read_buf[TAP_MAX_PKT_WRITE_LEN];
static uint8_t             rfcomm_read_buf[TAP_MAX_PKT_WRITE_LEN];

static int  rfcomm_net_register_service(void);
static void rfcomm_net_unregister_service(void);
static int  rfcomm_net_create_rfcomm_server(void);
static int  rfcomm_net_close_rfcomm_server(void);
static int  rfcomm_net_bridge_create(void);
static void rfcomm_net_bridge_close(void);
static int  rfcomm_net_get_bridge_state(char* net_name);

static int enable_cmd(int argc, char** argv)
{
    printf("enable server\n");
    int ret = rfcomm_net_create_rfcomm_server();
    if (ret) {
        printf("enable server fail\n");
    }
    return 0;
}

static int disable_cmd(int argc, char** argv)
{
    printf("disable server\n");
    rfcomm_net_close_rfcomm_server();
    return 0;
}

static int help_cmd(int argc, char** argv)
{
    printf("usage command\n");
    return 0;
}

static rfcomm_net_command_t cmd_table[] = {
    { "enable", enable_cmd, "enable tools" },
    { "disable", disable_cmd, "disable tools" },
    { "help", help_cmd, "help for tools" },
};

static void rfcomm_net_cmd_usage(void)
{
    printf("Commands:\n");
    for (int i = 0; i < sizeof(cmd_table) / sizeof(cmd_table[0]); i++) {
        printf("\t%-4s\t%s\n", cmd_table[i].cmd, cmd_table[i].help);
    }
}

static int rfcomm_net_execute_command(int argc, char* argv[])
{
    int ret;

    for (int i = 0; i < sizeof(cmd_table) / sizeof(cmd_table[0]); i++) {
        if (strcmp(cmd_table[i].cmd, argv[0]) == 0) {
            if (cmd_table[i].function) {
                ret = cmd_table[i].function(argc, argv);
                return ret;
            }
        }
    }

    printf("UnKnow command %s\n", argv[0]);
    rfcomm_net_cmd_usage();

    return -1;
}

static int rfcomm_net_tap_set_mac(const unsigned char* interface_name,
                                  const unsigned char* str_macaddr)
{
    int          ret;
    int          sock_fd;
    struct ifreq ifr;
    unsigned int mac2bit[6];

    if (interface_name == NULL || str_macaddr == NULL) {
        return -1;
    }

    sscanf((char*)str_macaddr, "%02X:%02X:%02X:%02X:%02X:%02X",
           (unsigned int*)&mac2bit[0], (unsigned int*)&mac2bit[1],
           (unsigned int*)&mac2bit[2], (unsigned int*)&mac2bit[3],
           (unsigned int*)&mac2bit[4], (unsigned int*)&mac2bit[5]);

    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        return -2;
    }

    sprintf(ifr.ifr_ifrn.ifrn_name, "%s", interface_name);
    ifr.ifr_ifru.ifru_hwaddr.sa_family  = 1;
    ifr.ifr_ifru.ifru_hwaddr.sa_data[0] = mac2bit[0];
    ifr.ifr_ifru.ifru_hwaddr.sa_data[1] = mac2bit[1];
    ifr.ifr_ifru.ifru_hwaddr.sa_data[2] = mac2bit[2];
    ifr.ifr_ifru.ifru_hwaddr.sa_data[3] = mac2bit[3];
    ifr.ifr_ifru.ifru_hwaddr.sa_data[4] = mac2bit[4];
    ifr.ifr_ifru.ifru_hwaddr.sa_data[5] = mac2bit[5];

    ret = ioctl(sock_fd, SIOCSIFHWADDR, &ifr);
    if (ret != 0) {
        return -4;
    }
    close(sock_fd);
    return 0;
}

static int rfcomm_net_tap_up(const unsigned char* interface_name)
{
    int                err;
    int                ret;
    int                socket_fd;
    struct ifreq       ifr;
    struct sockaddr_in sin;

    if (interface_name == NULL) {
        return -1;
    }

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        printf("Create Socket Failed.\n");
        return -2;
    }

    sprintf(ifr.ifr_name, "%s", interface_name);
    if ((err = ioctl(socket_fd, SIOCGIFFLAGS, (void*)&ifr)) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(socket_fd);
        return -3;
    }

    ifr.ifr_flags |= IFF_UP;
    ret = ioctl(socket_fd, SIOCSIFFLAGS, &ifr);
    if (ret != 0) {
        printf("Up Device %s Failed.\n", interface_name);
        close(socket_fd);
        return -4;
    }

    close(socket_fd);
    return 0;
}

static int rfcomm_net_tap_down(const unsigned char* interface_name)
{
    int                err;
    int                socket_fd;
    struct ifreq       ifr;
    struct sockaddr_in sin;

    if (interface_name == NULL) {
        return -1;
    }

    int state = rfcomm_net_get_bridge_state((char*)interface_name);
    if (state) {
        return 0;
    }

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        printf("Create Socket Failed.\n");
        return -2;
    }

    if ((err = ioctl(socket_fd, SIOCGIFFLAGS, (void*)&ifr)) < 0) {
        perror("ioctl SIOCGIFADDR");
        printf("Down Device %s Failed.\n", interface_name);
        close(socket_fd);
        return -3;
    }

    ifr.ifr_flags &= ~IFF_UP;
    if ((err = ioctl(socket_fd, SIOCGIFFLAGS, (void*)&ifr)) < 0) {
        perror("ioctl SIOCGIFADDR");
        printf("Down Device %s Failed.\n", interface_name);
        close(socket_fd);
        return -4;
    }

    close(socket_fd);
    return 0;
}

static int rfcomm_net_tap_open(const char* devname)
{
    struct ifreq ifr;
    uint8_t      local_addr[6], ethaddr[6];
    int          errcode;
    int          ret;

    g_rfcomm_net.tun_fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (g_rfcomm_net.tun_fd < 0) {
        errcode = errno;
        printf("ERROR: Failed to open /dev/tun: %d\n", errcode);
        return -errcode;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, devname, IFNAMSIZ - 1);
    ret = ioctl(g_rfcomm_net.tun_fd, TUNSETIFF, (unsigned long)&ifr);
    if (ret < 0) {
        errcode = errno;
        printf("ERROR: ioctl TUNSETIFF failed: %d\n", errcode);
        close(g_rfcomm_net.tun_fd);
        return -errcode;
    }

    memset(g_rfcomm_net.tun_devname, 0, IFNAMSIZ);
    strncpy(g_rfcomm_net.tun_devname, ifr.ifr_name, IFNAMSIZ);

    rfcomm_net_tap_set_mac(g_rfcomm_net.tun_devname, "00:1A:7D:8D:C8:41");
    rfcomm_net_tap_up(g_rfcomm_net.tun_devname);

    char bdaddr_str[18];
    ba2str((bdaddr_t*)ethaddr, bdaddr_str);
    bdaddr_str[17] = '\0';
    printf("Created Tap device: %s, Mac address: %s\n", ifr.ifr_name,
           bdaddr_str);

    return 0;
}

static void rfcomm_net_tap_close(void)
{
    if (g_rfcomm_net.tun_fd >= 0) {
        printf("TUN device: %s Closing\n", g_rfcomm_net.tun_devname);
        rfcomm_net_tap_down(g_rfcomm_net.tun_devname);
        close(g_rfcomm_net.tun_fd);
        g_rfcomm_net.tun_fd = -1;
    }
}

static void rfcomm_net_tap_poll_data(uv_poll_t* handle, int status, int events)
{
    ethernet_hdr_t ethhdr;

    if (events & UV_READABLE) {
        if (status == 0) {
            int ret = read(g_rfcomm_net.tun_fd, rfcomm_read_buf,
                           TAP_MAX_PKT_WRITE_LEN);
            if (ret > 0) {
                write(g_rfcomm_net.client_fd, rfcomm_read_buf, ret);
            }

            printf("%s poll ret:%d\n", __func__, ret);
            return;
        } else {
            printf("%s poll status:%d\n", __func__, status);
            return;
        }

    } else {
        printf("%s poll disconnected\n", __func__);
        rfcomm_net_tap_close();
    }
}

static void rfcomm_net_rfcomm_poll_data(uv_poll_t* handle, int status,
                                        int events)
{
    ethernet_hdr_t ethhdr;

    if (events & UV_READABLE) {
        if (status == 0) {
            int ret = read(g_rfcomm_net.client_fd, tun_read_buf,
                           TAP_MAX_PKT_WRITE_LEN);
            if (ret > 0) {
                write(g_rfcomm_net.tun_fd, tun_read_buf, ret);
            }

            printf("%s poll ret:%d\n", __func__, ret);
            return;
        } else {
            printf("%s poll status:%d\n", __func__, status);
            return;
        }

    } else {
        printf("%s poll disconnected\n", __func__);
        rfcomm_net_close_rfcomm_server();
    }
}

static uv_poll_t* rfcomm_net_uv_poll_start(int fd, int pevents, uv_poll_cb cb,
                                           void* userdata)
{
    uv_poll_t* handle = (uv_poll_t*)malloc(sizeof(uv_poll_t));
    if (!handle) {
        printf("malloc uv_poll_t failed\n");
        return NULL;
    }
    handle->data = userdata;

    int ret = uv_poll_init(g_rfcomm_net.loop, handle, fd);
    if (ret < 0) {
        printf("uv_poll_init failed: %d\n", ret);
        free(handle);
        return NULL;
    }

    ret = uv_poll_start(handle, pevents, cb);
    if (ret < 0) {
        printf("uv_poll_start failed: %d\n", ret);
        free(handle);
        return NULL;
    }

    return handle;
}

static void rfcomm_net_uv_close_cb(uv_handle_t* handle) { free(handle); }

static void rfcomm_net_uv_poll_stop(uv_poll_t* handle)
{
    if (!handle) {
        return;
    }

    uv_poll_stop(handle);
    uv_close((uv_handle_t*)handle, rfcomm_net_uv_close_cb);
}

static int rfcomm_net_iface_add_to_bridge(const char* devname,
                                          const char* bridge)
{
    int          ifindex;
    struct ifreq ifr;
    int          sk, err = 0;

    if (!devname || !bridge)
        return -EINVAL;

    ifindex = if_nametoindex(devname);

    sk = socket(AF_INET, SOCK_STREAM, 0);
    if (sk < 0)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, bridge, IFNAMSIZ - 1);
    ifr.ifr_ifindex = ifindex;

    if (ioctl(sk, SIOCBRADDIF, &ifr) < 0) {
        err = -errno;
        printf("Can't add %s to the bridge %s: %s(%d)\n", devname, bridge,
               strerror(-err), -err);
    } else {
        printf("bridge %s: interface %s added\n", bridge, devname);
    }

    close(sk);

    return err;
}

static int rfcomm_net_iface_del_from_bridge(const char* devname,
                                            const char* bridge)
{
    int          ifindex;
    struct ifreq ifr;
    int          sk, err = 0;

    if (!devname || !bridge)
        return -EINVAL;

    struct ifaddrs *ifa = NULL, *ifList;
    if (getifaddrs(&ifList) < 0) {
        return -1;
    }
    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, TAP_IFNAME) == 0) {
            break;
        }
    }
    freeifaddrs(ifList);
    if (ifa == NULL) {
        return -1;
    }

    ifindex = if_nametoindex(devname);
    sk      = socket(AF_INET, SOCK_STREAM, 0);
    if (sk < 0)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, bridge, IFNAMSIZ - 1);
    ifr.ifr_ifindex = ifindex;

    if (ioctl(sk, SIOCBRDELIF, &ifr) < 0) {
        err = -errno;
        printf("Can't delete %s from the bridge %s: %s(%d)\n", devname, bridge,
               strerror(-err), -err);
    } else {
        printf("bridge %s: interface %s removed\n", bridge, devname);
    }

    close(sk);

    return err;
}

static int rfcomm_net_get_bridge_state(char* net_name)
{
    int          skfd = 0;
    struct ifreq ifr;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (skfd < 0) {
        printf("%s:%d Open socket error!\n", __FILE__, __LINE__);
        return -1;
    }

    strcpy(ifr.ifr_name, net_name);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        printf("maybe inferface %s is not valid\n", ifr.ifr_name);
        close(skfd);
        return -1;
    }

    close(skfd);
    if (!(ifr.ifr_flags & IFF_RUNNING)) {
        return -1;
    }

    return 0;
}

static int rfcomm_net_register_service(void)
{
    int ret = 0;

    uint32_t uuid_int[] = { 0x01110000, 0x00100000, 0x80000080, 0xFB349B5F };
    uint8_t* uuid_ptr   = (uint8_t*)&uuid_int[0];
    uuid_ptr[2]         = (RFCOMM_NET_SERVER_UUID >> 8) & 0xFF;
    uuid_ptr[3]         = RFCOMM_NET_SERVER_UUID & 0xFF;

    uint8_t     rfcomm_channel = RFCOMM_CHANNEL;
    const char* service_name   = "Rfcomm server";
    const char* service_dsc    = "server of net proxy by rfcomm.";
    const char* service_prov   = "YJ";

    uuid_t      root_uuid, l2cap_uuid, rfcomm_uuid, svc_uuid;
    sdp_list_t *l2cap_list = 0, *rfcomm_list = 0, *root_list = 0,
               *proto_list = 0, *access_proto_list = 0;
    sdp_data_t *channel = 0, *psm = 0;

    g_sdp_service.rec = sdp_record_alloc();

    // set the general service ID
    sdp_uuid128_create(&svc_uuid, &uuid_int);
    sdp_set_service_id(g_sdp_service.rec, svc_uuid);
    sdp_list_t service_class = { NULL, &svc_uuid };
    sdp_set_service_classes(g_sdp_service.rec, &service_class);

    // make the service record publicly browsable
    sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
    root_list = sdp_list_append(0, &root_uuid);
    sdp_set_browse_groups(g_sdp_service.rec, root_list);

    // set l2cap information
    sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
    l2cap_list = sdp_list_append(0, &l2cap_uuid);
    proto_list = sdp_list_append(0, l2cap_list);

    // set rfcomm information
    sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
    channel     = sdp_data_alloc(SDP_UINT8, &rfcomm_channel);
    rfcomm_list = sdp_list_append(0, &rfcomm_uuid);
    sdp_list_append(rfcomm_list, channel);
    sdp_list_append(proto_list, rfcomm_list);

    // attach protocol information to service record
    access_proto_list = sdp_list_append(0, proto_list);
    sdp_set_access_protos(g_sdp_service.rec, access_proto_list);

    // set profile discription
    sdp_set_profile_descs(g_sdp_service.rec, &service_class);

    // set the name, provider, and description
    sdp_set_info_attr(g_sdp_service.rec, service_name, service_prov,
                      service_dsc);

    int err               = 0;
    g_sdp_service.session = 0;

    // connect to the local SDP server, register the service record, and
    // disconnect
    g_sdp_service.session
        = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, SDP_RETRY_IF_BUSY);
    if (g_sdp_service.session == NULL) {
        sdp_record_free(g_sdp_service.rec);
        ret = -1;
    }

    err = sdp_record_register(g_sdp_service.session, g_sdp_service.rec, 0);
    if (err == -1) {
        sdp_close(g_sdp_service.session);
        sdp_record_free(g_sdp_service.rec);
        ret = -2;
    }

    // cleanup
    // sdp_data_free( channel );
    sdp_list_free(l2cap_list, 0);
    sdp_list_free(rfcomm_list, 0);
    sdp_list_free(root_list, 0);
    sdp_list_free(access_proto_list, 0);
    return ret;
}

static void rfcomm_net_unregister_service(void)
{
    if (g_sdp_service.session) {
        sdp_record_register(g_sdp_service.session, g_sdp_service.rec, 0);
        sdp_close(g_sdp_service.session);
    }

    if (g_sdp_service.rec) {
        sdp_record_free(g_sdp_service.rec);
    }
}

static int rfcomm_net_bridge_create(void)
{
    struct ifaddrs *ifa = NULL, *ifList;

    if (getifaddrs(&ifList) < 0) {
        return -1;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "ifconfig %s %s up", BR_IFNAME, GATEWAY_ADDR);

    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, BR_IFNAME) == 0) {
            if (rfcomm_net_get_bridge_state(BR_IFNAME) != 0) {
                system(buf);
            }
            freeifaddrs(ifList);
            return 0;
        }
    }

    snprintf(buf, sizeof(buf), "sudo brctl addbr %s", BR_IFNAME);
    system(buf);

    snprintf(buf, sizeof(buf), "ifconfig %s %s up", BR_IFNAME, GATEWAY_ADDR);
    system(buf);

    freeifaddrs(ifList);
    return 0;
}

static void rfcomm_net_bridge_close(void)
{
    struct ifaddrs *ifa = NULL, *ifList;

    if (getifaddrs(&ifList) < 0) {
        return;
    }

    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, BR_IFNAME) == 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "ifconfig %s %s down", BR_IFNAME,
                     GATEWAY_ADDR);
            system(buf);

            snprintf(buf, sizeof(buf), "sudo brctl delbr %s", BR_IFNAME);
            system(buf);

            freeifaddrs(ifList);
            return;
        }
    }

    freeifaddrs(ifList);
}

static int rfcomm_net_create_rfcomm_server(void)
{
    struct sockaddr_rc loc_addr = { 0 }, rem_addr = { 0 };
    char               buf[64] = { 0 };
    int                s, client, bytes_read;
    socklen_t          opt = sizeof(rem_addr);

    int ret = rfcomm_net_register_service();
    if (ret != 0) {
        goto fail;
    }

    printf("create rfcomm server\n");

    g_rfcomm_net.rfcomm_fd = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    loc_addr.rc_family     = AF_BLUETOOTH;
    loc_addr.rc_bdaddr     = *BDADDR_ANY;
    loc_addr.rc_channel    = (uint8_t)RFCOMM_CHANNEL;
    bind(g_rfcomm_net.rfcomm_fd, (struct sockaddr*)&loc_addr, sizeof(loc_addr));

    printf("listen...\n");
    listen(g_rfcomm_net.rfcomm_fd, 1);

    printf("accept...\n");
    g_rfcomm_net.client_fd
        = accept(g_rfcomm_net.rfcomm_fd, (struct sockaddr*)&rem_addr, &opt);

    ba2str(&rem_addr.rc_bdaddr, buf);
    printf("accepted connection from %s\n", buf);

    g_rfcomm_net.spp_poll_handle = rfcomm_net_uv_poll_start(
        g_rfcomm_net.client_fd, UV_DISCONNECT | UV_READABLE,
        rfcomm_net_rfcomm_poll_data, NULL);

    ret = rfcomm_net_bridge_create();
    if (ret != 0) {
        goto fail;
    }

    ret = rfcomm_net_tap_open(TAP_IFNAME);
    if (ret) {
        printf("open tap fail\n");
        goto fail;
    }

    g_rfcomm_net.tun_poll_handle = rfcomm_net_uv_poll_start(
        g_rfcomm_net.tun_fd, UV_DISCONNECT | UV_READABLE,
        rfcomm_net_tap_poll_data, NULL);

    ret = rfcomm_net_iface_add_to_bridge(TAP_IFNAME, BR_IFNAME);
    if (ret) {
        printf("add iface to bridge fail\n");
        goto fail;
    }

    return ret;

fail:
    rfcomm_net_close_rfcomm_server();
    return ret;
}

static int rfcomm_net_close_rfcomm_server(void)
{
    rfcomm_net_iface_del_from_bridge(TAP_IFNAME, BR_IFNAME);

    rfcomm_net_uv_poll_stop(g_rfcomm_net.spp_poll_handle);
    g_rfcomm_net.spp_poll_handle = NULL;

    rfcomm_net_uv_poll_stop(g_rfcomm_net.tun_poll_handle);
    g_rfcomm_net.tun_poll_handle = NULL;

    if (g_rfcomm_net.client_fd) {
        close(g_rfcomm_net.client_fd);
        g_rfcomm_net.client_fd = -1;
    }

    if (g_rfcomm_net.rfcomm_fd) {
        close(g_rfcomm_net.rfcomm_fd);
        g_rfcomm_net.rfcomm_fd = -1;
    }

    rfcomm_net_tap_close();
    rfcomm_net_bridge_close();
    rfcomm_net_unregister_service();
}

static void rfcomm_net_command_alloc(uv_handle_t* handle, size_t suggested_size,
                                     uv_buf_t* buf)
{
    *buf = uv_buf_init((char*)malloc(suggested_size), suggested_size);
}

static void rfcomm_net_command_read_stdin(uv_stream_t* stream, ssize_t nread,
                                          const uv_buf_t* buf)
{
    printf("rfcomm_server> ");
    fflush(stdout);
    if (nread < 0) {
        if (nread == UV_EOF) {
            uv_close((uv_handle_t*)&g_rfcomm_net.stdin_pipe, NULL);
        }
    } else if (nread > 1) {
        int   cnt     = 0;
        char* saveptr = NULL;
        char* _argv[10];
        char* tmpstr      = buf->base;
        tmpstr[nread - 1] = '\0';
        while ((tmpstr = strtok_r(tmpstr, " ", &saveptr)) && cnt < 10) {
            _argv[cnt++] = tmpstr;
            tmpstr       = NULL;
        }

        if (cnt > 0) {
            rfcomm_net_execute_command(cnt, _argv);
        }
    }

    if (buf->base)
        free(buf->base);
}

static int rfcomm_net_command_start(void)
{
    uv_pipe_init(g_rfcomm_net.loop, &g_rfcomm_net.stdin_pipe, 0);
    uv_pipe_open(&g_rfcomm_net.stdin_pipe, 0);
    uv_read_start((uv_stream_t*)&g_rfcomm_net.stdin_pipe,
                  rfcomm_net_command_alloc, rfcomm_net_command_read_stdin);
    printf("rfcomm_server> ");
    fflush(stdout);
    return 0;
}

int main(int argc, char** argv)
{
    g_rfcomm_net.tun_fd    = -1;
    g_rfcomm_net.rfcomm_fd = -1;
    g_rfcomm_net.client_fd = -1;
    g_rfcomm_net.loop      = malloc(sizeof(uv_loop_t));

    uv_loop_init(g_rfcomm_net.loop);
    rfcomm_net_command_start();

    uv_run(g_rfcomm_net.loop, UV_RUN_DEFAULT);

    uv_loop_close(g_rfcomm_net.loop);
    free(g_rfcomm_net.loop);

    return 0;
}

// gcc rfcomm_net_server.c -lbluetooth -luv -o rfcomm_test