#include "common.h"

struct {
    enum {
        RFCOMM_IP_FRAME_STATE_START = 0,
        RFCOMM_IP_FRAME_STATE_LEN_LOW,
        RFCOMM_IP_FRAME_STATE_LEN_HIGH,
        RFCOMM_IP_FRAME_STATE_BODY,
        RFCOMM_IP_FRAME_STATE_XOR,
        RFCOMM_IP_FRAME_STATE_END,
    } state;

    int     offset;
    int     length;
    uint8_t data[TAP_MAX_PKT_WRITE_LEN];
} recv_ctrl;

uv_pipe_t stdin_pipe;

void syslog(int level, const char* fmt, ...)
{
    if (level >= RECOMM_NET_LOG_LEVEL || level == 4) {
        char           buf[64] = { 0 };
        struct timeval tv      = { 0 };
        struct tm      tm      = { 0 };

        if (level != 4) {
            gettimeofday(&tv, NULL);
            localtime_r(&tv.tv_sec, &tm);
            strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
            printf("[%s.%06ld]", buf, tv.tv_usec);
        }

        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }
}

void rfcomm_net_list_init(struct list_node* list)
{
    list->next = list;
    list->prev = list;
}

void rfcomm_net_list_add_item(struct list_node* list, struct list_node* item)
{
    item->prev       = list->prev;
    item->next       = list;
    list->prev->next = item;
    list->prev       = item;
}

void rfcomm_net_list_del_item(struct list_node* item, del_cb cb)
{
    item->next->prev = item->prev;
    item->prev->next = item->next;
    item->prev = item->next = NULL;
    cb(item);
}

int rfcomm_net_list_traversal(struct list_node* list, check_cb cb, int index)
{
    struct list_node* item;
    for (item = list->next; item != list; item = item->next) {
        if (cb(item, index)) {
            return 0;
        }
    }

    return -1;
}

void rfcomm_net_list_destroy(struct list_node* list, del_cb cb)
{
    struct list_node *item, *next;
    for (item = list->next; item != list; item = next) {
        next = item->next;
        cb(item);
    }

    list->prev = list->next = list;
}

static int rfcomm_net_escape(uint8_t* in, int ilen, uint8_t* out, int* olen)
{
    int i, j;
    if (in == NULL || out == NULL) {
        return -1;
    }

    for (i = 0, j = 0; i < ilen && j < *olen; i++) {
        if (in[i] == 0x5B && in[i] == 0x5C && in[i] == 0x5D) {
            if (j + 1 >= *olen) {
                *olen = j;
                return 0;
            }

            out[j++] = 0x5B;
            out[j++] = in[i] - 0x5B;
        } else {
            out[j++] = in[i];
        }
    }

    if (i != ilen) {
        return -1;
    }

    *olen = j;
    return j;
}

static int rfcomm_net_data_unescape(uint8_t* in, int ilen, uint8_t* out,
                                    int olen)
{
    int i, j;
    if (in == NULL || out == NULL) {
        return 0;
    }

    for (i = 0, j = 0; i + 1 < ilen && j < olen; i++) {
        if (in[i] == 0x5B) {
            if (i + 1 >= ilen) {
                return -1;
            }

            out[j++] = 0x5B + in[++i];
        } else {
            out[j++] = in[i];
        }
    }

    if (i != ilen) {
        return 0;
    }

    return j;
}

uint8_t rfcomm_net_xor_calculate(uint8_t* data, int len)
{
    uint8_t res = 0;

    for (int i = 0; i < len; i++) {
        res = res ^ data[i];
    }

    return res;
}

void rfcomm_net_hex_print(char* tag, uint8_t* data, int len)
{
#if RECOMM_NET_SUPPORT_DATA_PRINT
    RAW_("%s:\n", tag);
    for (int j = 0; j < len; j++) {
        RAW_("%02X\n", data[j]);
        if (j % 16 == 15) {
            RAW_("\n");
        }
    }
    RAW_("\n");
#endif
}

void rfcomm_net_protocol_send(int fd, uint8_t* data, int len)
{
    if (data == NULL || len <= 0 || len > TAP_MAX_PKT_WRITE_LEN) {
        ERROR_("send data fail:%d\n", len);
        return;
    }

    uint8_t buf[TAP_MAX_PKT_WRITE_LEN + 5];
    buf[0] = 0x5C;
    buf[1] = len & 0x00FF;
    buf[2] = (len >> 8) & 0x00FF;
    memcpy(buf + 3, data, len);
#if RECOMM_NET_SUPPORT_XOR_CHECK
    buf[3 + len] = rfcomm_net_xor_calculate(buf + 3, len);
#endif
    buf[4 + len] = 0x5D;
    write(fd, buf, len + 5);
    rfcomm_net_hex_print("send:", data, len);
}

void rfcomm_net_protocol_receive(int fd, uint8_t* data, int len)
{
    int i = 0, needs;
    uint8_t xor ;
    if (data == NULL || len <= 0) {
        ERROR_("receive data anomaly\n");
        return;
    }

    while (i < len) {
        switch (recv_ctrl.state) {
        case RFCOMM_IP_FRAME_STATE_START:
            if (data[i++] != 0x5C) {
                continue;
            }
            recv_ctrl.offset = 0;
            recv_ctrl.length = 0;
            break;

        case RFCOMM_IP_FRAME_STATE_LEN_LOW:
            recv_ctrl.length = data[i++];
            break;

        case RFCOMM_IP_FRAME_STATE_LEN_HIGH:
            recv_ctrl.length += (data[i++] << 8);
            if (recv_ctrl.length > TAP_MAX_PKT_WRITE_LEN) {
                recv_ctrl.state = RFCOMM_IP_FRAME_STATE_START;
                continue;
            }
            break;

        case RFCOMM_IP_FRAME_STATE_BODY:
            needs = recv_ctrl.length - recv_ctrl.offset;
            if (len - i < needs) {
                memcpy(recv_ctrl.data + recv_ctrl.offset, data + i, len - i);
                recv_ctrl.offset += len - i;
                i = len;
                continue;
            }
            memcpy(recv_ctrl.data + recv_ctrl.offset, data + i, needs);
            recv_ctrl.offset = recv_ctrl.length;
            i += needs;
            break;

        case RFCOMM_IP_FRAME_STATE_XOR:
#if RECOMM_NET_SUPPORT_XOR_CHECK
            xor = rfcomm_net_xor_calculate(recv_ctrl.data, recv_ctrl.offset);
            if (recv_ctrl.data[i] != xor) {
                recv_ctrl.state = RFCOMM_IP_FRAME_STATE_START;
                continue;
            }
#endif
            break;

        case RFCOMM_IP_FRAME_STATE_END:
            if (data[i++] == 0x5D) {
                write(fd, recv_ctrl.data, recv_ctrl.offset);
                rfcomm_net_hex_print("rcv:", recv_ctrl.data, recv_ctrl.offset);
            }
            recv_ctrl.state = RFCOMM_IP_FRAME_STATE_START;
            continue;

        default:
            ERROR_("unknown state:%u\n", recv_ctrl.state);
            continue;
        }

        recv_ctrl.state++;
    }
}

int rfcomm_net_get_host_bt_addr(bdaddr_t* addr)
{
    int                 dev_id;
    struct hci_dev_info dev_info;

    dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        ERROR_("Can't get device ID\n");
        return -1;
    }

    if (hci_devinfo(dev_id, &dev_info) < 0) {
        ERROR_("Can't get device info\n");
        return -1;
    }

    memcpy(addr, &dev_info.bdaddr, sizeof(bdaddr_t));
    return 0;
}

int rfcomm_net_iface_set_mac(const char* if_name, const char* mac)
{
    int          ret;
    int          sock_fd;
    struct ifreq ifr = { 0 };
    unsigned int mac2bit[6];

    INFO_("set mac: %s\n", mac);

    if (if_name == NULL || mac == NULL) {
        ERROR_("iface or mac null\n");
        return -1;
    }

    sscanf((char*)mac, "%02X:%02X:%02X:%02X:%02X:%02X",
           (unsigned int*)&mac2bit[0], (unsigned int*)&mac2bit[1],
           (unsigned int*)&mac2bit[2], (unsigned int*)&mac2bit[3],
           (unsigned int*)&mac2bit[4], (unsigned int*)&mac2bit[5]);

    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        ERROR_("open socket failed\n");
        return -2;
    }

    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    ifr.ifr_ifru.ifru_hwaddr.sa_family  = 1;
    ifr.ifr_ifru.ifru_hwaddr.sa_data[0] = mac2bit[0];
    ifr.ifr_ifru.ifru_hwaddr.sa_data[1] = mac2bit[1];
    ifr.ifr_ifru.ifru_hwaddr.sa_data[2] = mac2bit[2];
    ifr.ifr_ifru.ifru_hwaddr.sa_data[3] = mac2bit[3];
    ifr.ifr_ifru.ifru_hwaddr.sa_data[4] = mac2bit[4];
    ifr.ifr_ifru.ifru_hwaddr.sa_data[5] = mac2bit[5];

    ret = ioctl(sock_fd, SIOCSIFHWADDR, &ifr);
    if (ret != 0) {
        ERROR_("update %s SIOCSIFHWADDR failed:%d\n", if_name, ret);
        return -3;
    }
    close(sock_fd);
    return 0;
}

int rfcomm_net_iface_up(const char* if_name)
{
    int                socket_fd;
    struct ifreq       ifr = { 0 };
    struct sockaddr_in sin;

    if (if_name == NULL) {
        ERROR_("iface null\n");
        return -1;
    }

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        ERROR_("create socket failed\n");
        return -2;
    }

    strncpy(ifr.ifr_name, if_name, IF_NAMESIZE - 1);
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(socket_fd, SIOCSIFFLAGS, &ifr) < 0) {
        ERROR_("update ifr failed:%s\n", strerror(errno));
        close(socket_fd);
        return -4;
    }

    close(socket_fd);
    return 0;
}

int rfcomm_net_iface_down(const char* if_name)
{
    int                socket_fd;
    struct ifreq       ifr = { 0 };
    struct sockaddr_in sin;

    if (if_name == NULL) {
        ERROR_("iface null\n");
        return -1;
    }

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        ERROR_("open socket failed\n");
        return -2;
    }

    strncpy(ifr.ifr_name, if_name, IF_NAMESIZE - 1);
    ifr.ifr_flags &= ~IFF_UP;
    if (ioctl(socket_fd, SIOCSIFFLAGS, (void*)&ifr) < 0) {
        ERROR_("update ifr Failed:%s\n", strerror(errno));
        close(socket_fd);
        return -4;
    }

    close(socket_fd);
    return 0;
}

int rfcomm_net_iface_set_ip(char* ip, char* br_name)
{
    struct ifreq       ifr;
    struct sockaddr_in sin;
    int                sk, err;

    sk = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, br_name, IF_NAMESIZE - 1);

    memset(&sin, 0, sizeof(struct sockaddr));
    sin.sin_family = AF_INET;
    inet_aton(ip, &sin.sin_addr);
    memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));

    err = ioctl(sk, SIOCSIFADDR, (caddr_t)&ifr);
    close(sk);
    if (err < 0) {
        ERROR_("could not set ip:%s\n", br_name);
        return err;
    }

    return 0;
}

int rfcomm_net_iface_get_state(char* net_name)
{
    int          skfd = 0;
    struct ifreq ifr;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (skfd < 0) {
        ERROR_("open socket error\n");
        return -1;
    }

    strcpy(ifr.ifr_name, net_name);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        ERROR_("maybe inferface %s is not valid\n", ifr.ifr_name);
        close(skfd);
        return -1;
    }

    close(skfd);
    if (!(ifr.ifr_flags & IFF_RUNNING)) {
        return -1;
    }

    return 0;
}

int rfcomm_net_tap_open(const char* if_name, const char* mac_addr)
{
    struct ifreq ifr;
    int          tap_fd = 0;
    int          ret;

    tap_fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (tap_fd < 0) {
        ERROR_("failed to open /dev/net/tun: %d\n", errno);
        return -errno;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    ret = ioctl(tap_fd, TUNSETIFF, (unsigned long)&ifr);
    if (ret < 0) {
        ERROR_("ioctl TUNSETIFF failed: %d\n", errno);
        return -errno;
    }

    rfcomm_net_iface_set_mac(if_name, mac_addr);
    rfcomm_net_iface_up(if_name);

    int sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        ERROR_("open socket failed\n");
        return -2;
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    ret = ioctl(sock_fd, SIOCGIFHWADDR, &ifr);
    if (ret != 0) {
        ERROR_("update SIOCGIFHWADDR failed\n");
        return -3;
    }
    close(sock_fd);

    char bdaddr_str[18];
    ba2str((bdaddr_t*)ifr.ifr_ifru.ifru_hwaddr.sa_data, bdaddr_str);
    bdaddr_str[17] = '\0';
    INFO_("created tap: %s, mac address: %s\n", ifr.ifr_name, bdaddr_str);

    return tap_fd;
}

void rfcomm_net_tap_close(const char* if_name, int tap_fd)
{
    if (tap_fd > 0) {
        INFO_("tap device: %s closing\n", if_name);
        rfcomm_net_iface_down(if_name);
        close(tap_fd);
    }
}

uv_poll_t* rfcomm_net_uv_poll_start(uv_loop_t* loop, int fd, int pevents,
                                    uv_poll_cb cb, void* userdata)
{
    uv_poll_t* handle = (uv_poll_t*)malloc(sizeof(uv_poll_t));
    if (!handle) {
        ERROR_("malloc uv_poll_t failed\n");
        return NULL;
    }
    handle->data = userdata;

    int ret = uv_poll_init(loop, handle, fd);
    if (ret < 0) {
        ERROR_("uv_poll_init failed: %d\n", ret);
        free(handle);
        return NULL;
    }

    ret = uv_poll_start(handle, pevents, cb);
    if (ret < 0) {
        ERROR_("uv_poll_start failed: %d\n", ret);
        free(handle);
        return NULL;
    }

    return handle;
}

static void rfcomm_net_uv_close_cb(uv_handle_t* handle) { free(handle); }

void rfcomm_net_uv_poll_stop(uv_poll_t* handle)
{
    if (!handle) {
        return;
    }

    uv_poll_stop(handle);
    uv_close((uv_handle_t*)handle, rfcomm_net_uv_close_cb);
}

static void rfcomm_net_command_alloc(uv_handle_t* handle, size_t suggested_size,
                                     uv_buf_t* buf)
{
    *buf = uv_buf_init((char*)malloc(suggested_size), suggested_size);
}

static void rfcomm_net_command_read_stdin(uv_stream_t* stream, ssize_t nread,
                                          const uv_buf_t* buf)
{
    RAW_("rfcomm_net> ");
    fflush(stdout);

    if (nread < 0) {
        if (nread == UV_EOF) {
            uv_close((uv_handle_t*)&stdin_pipe, NULL);
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
            RAW_("\n");
            ((cmd_cb)(stdin_pipe.data))(cnt, _argv);
        }
    }

    if (buf->base) {
        free(buf->base);
    }
}

int rfcomm_net_command_start(uv_loop_t* loop, cmd_cb cb)
{
    if (loop == NULL || cb == NULL) {
        ERROR_("command start fail\n");
        return -1;
    }

    uv_pipe_init(loop, &stdin_pipe, 0);
    uv_pipe_open(&stdin_pipe, 0);
    stdin_pipe.data = (void*)cb;
    uv_read_start((uv_stream_t*)&stdin_pipe, rfcomm_net_command_alloc,
                  rfcomm_net_command_read_stdin);
    RAW_("rfcomm_net> ");
    fflush(stdout);
    return 0;
}

int rfcomm_net_command_stop(void)
{
    uv_close((uv_handle_t*)&stdin_pipe, NULL);
    return 0;
}
