#include "common.h"

#define SERVER_TAP_IFNAME "bt-net%d"
#define SERVER_BR_IFNAME "bt-bridge"
#define SERVER_BR_IP "192.168.10.1"
#define SERVER_SUPPORT_CLIENT_NUM 10
#define SERVER_BT_CHANNEL 11
#define SERVER_BT_UUID 0x1101

typedef struct {
    int rfcomm_fd;
    uv_poll_t* server_poll_handle;
    uv_loop_t* loop;
} server_service_t;
static server_service_t g_server_service = {
    .rfcomm_fd = -1,
};

typedef struct {
    struct list_node node;
    int index;
    int tap_fd;
    int client_fd;
    uv_poll_t* tap_poll_handle;
    uv_poll_t* client_poll_handle;
} client_handle_t;

typedef struct sdp_service {
    sdp_session_t* session;
    sdp_record_t* rec;
} sdp_service_t;
static sdp_service_t g_sdp_service;

struct list_node client_list;

static int rfcomm_server_create(void);
static int rfcomm_server_close(void);
static int rfcomm_server_accept_client(void);
static void rfcomm_server_close_client(struct list_node* handle);
static void rfcomm_server_cmd_usage(void);

static int rfcomm_server_cmd_enable(int argc, char** argv)
{
    int ret = rfcomm_server_create();
    if (ret) {
        ERROR_("enable server fail\n");
    }
    return 0;
}

static int rfcomm_server_cmd_disable(int argc, char** argv)
{
    rfcomm_server_close();
    return 0;
}

static int rfcomm_server_cmd_help(int argc, char** argv)
{
    rfcomm_server_cmd_usage();
    return 0;
}

static rfcomm_net_command_t cmd_table[] = {
    { "enable", rfcomm_server_cmd_enable, "enable server" },
    { "disable", rfcomm_server_cmd_disable, "disable server" },
    { "help", rfcomm_server_cmd_help, "help for tools" },
};

static void rfcomm_server_cmd_usage(void)
{
    RAW_("Commands:\n");
    for (int i = 0; i < sizeof(cmd_table) / sizeof(cmd_table[0]); i++) {
        RAW_("\t%-4s\t%s\n", cmd_table[i].cmd, cmd_table[i].help);
    }
}

static int rfcomm_server_cmd_execute(int argc, char* argv[])
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

    WARN_("unknow command %s\n", argv[0]);
    rfcomm_server_cmd_usage();

    return -1;
}

static void rfcomm_server_item_free(struct list_node* item)
{
    if (item) {
        free(item);
    }
}

static int rfcomm_server_check_by_index(struct list_node* item, int index)
{
    client_handle_t* client_handle = (client_handle_t*)item;
    if (client_handle->index == index) {
        return 1;
    }

    return 0;
}

static int rfcomm_server_bridge_add_iface(const char* if_name, const char* bridge)
{
    int ifindex;
    struct ifreq ifr;
    int sk, err = 0;

    if (!if_name || !bridge) {
        ERROR_("iface null\n");
        return -EINVAL;
    }

    ifindex = if_nametoindex(if_name);

    sk = socket(AF_INET, SOCK_STREAM, 0);
    if (sk < 0)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, bridge, IFNAMSIZ - 1);
    ifr.ifr_ifindex = ifindex;

    if (ioctl(sk, SIOCBRADDIF, &ifr) < 0) {
        err = -errno;
        ERROR_("can't add %s to the bridge %s: %s(%d)\n", if_name, bridge,
            strerror(-err), -err);
    }

    close(sk);
    return err;
}

static int rfcomm_server_bridge_del_iface(const char* if_name, const char* bridge)
{
    int ifindex;
    struct ifreq ifr;
    int sk, err = 0;

    if (!if_name || !bridge) {
        ERROR_("iface null\n");
        return -EINVAL;
    }

    struct ifaddrs *ifa = NULL, *ifList;
    if (getifaddrs(&ifList) < 0) {
        ERROR_("getifaddrs fail\n");
        return -1;
    }
    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, if_name) == 0) {
            break;
        }
    }
    freeifaddrs(ifList);
    if (ifa == NULL) {
        return -1;
    }

    ifindex = if_nametoindex(if_name);
    sk = socket(AF_INET, SOCK_STREAM, 0);
    if (sk < 0) {
        ERROR_("open socket fail\n");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, bridge, IFNAMSIZ - 1);
    ifr.ifr_ifindex = ifindex;

    if (ioctl(sk, SIOCBRDELIF, &ifr) < 0) {
        err = -errno;
        ERROR_("can't delete %s from the bridge %s: %s(%d)\n", if_name, bridge,
            strerror(-err), -err);
    }

    close(sk);
    return err;
}

static int rfcomm_server_bridge_set_forward_delay(int sk)
{
    unsigned long args[4] = { BRCTL_SET_BRIDGE_FORWARD_DELAY, 0, 0, 0 };
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, SERVER_BR_IFNAME, IFNAMSIZ - 1);
    ifr.ifr_data = (char*)args;

    if (ioctl(sk, SIOCDEVPRIVATE, &ifr) < 0) {
        ERROR_("set forward delay failed: %d (%s)\n", errno, strerror(errno));
        return -1;
    }

    return 0;
}

static int rfcomm_server_bridge_create(void)
{
    int sk, err;

    sk = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sk < 0)
        return -EOPNOTSUPP;

    if (ioctl(sk, SIOCBRADDBR, SERVER_BR_IFNAME) < 0) {
        err = -errno;
        if (err != -EEXIST) {
            ERROR_("could not create br: %s\n", SERVER_BR_IFNAME);
            close(sk);
            return -EOPNOTSUPP;
        }
    }

    err = rfcomm_server_bridge_set_forward_delay(sk);
    if (err < 0) {
        ioctl(sk, SIOCBRDELBR, SERVER_BR_IFNAME);
    }

    close(sk);
    return err;
}

static int rfcomm_server_bridge_remove(void)
{
    int sk, err;
    rfcomm_net_iface_down(SERVER_BR_IFNAME);

    sk = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sk < 0)
        return -EOPNOTSUPP;

    err = ioctl(sk, SIOCBRDELBR, SERVER_BR_IFNAME);
    if (err < 0)
        err = -errno;

    close(sk);

    if (err < 0)
        return err;

    return 0;
}

static void rfcomm_server_poll_tap_data(uv_poll_t* handle, int status, int events)
{
    uint8_t buf[TAP_MAX_PKT_WRITE_LEN];
    client_handle_t* client_handle = (client_handle_t*)(handle->data);

    if (events & UV_READABLE) {
        if (status == 0) {
            int ret = read(client_handle->tap_fd, buf, TAP_MAX_PKT_WRITE_LEN);
            if (ret > 0) {
                rfcomm_net_protocol_send(client_handle->client_fd, buf, ret);
            }

            INFO_("poll ret:%d\n", ret);
            return;
        } else {
            INFO_("poll status:%d\n", status);
            return;
        }

    } else {
        INFO_("poll disconnected\n");
        rfcomm_server_close_client(handle->data);
    }
}

static void rfcomm_server_poll_client_data(uv_poll_t* handle, int status, int events)
{
    uint8_t buf[TAP_MAX_PKT_WRITE_LEN];
    client_handle_t* client_handle = (client_handle_t*)(handle->data);

    if (events & UV_READABLE) {
        if (status == 0) {
            int ret = read(client_handle->client_fd, buf, TAP_MAX_PKT_WRITE_LEN);
            if (ret > 0) {
                rfcomm_net_protocol_receive(client_handle->tap_fd, buf, ret);
            }

            INFO_("poll ret:%d\n", ret);
            return;
        } else {
            INFO_("poll status:%d\n", status);
            return;
        }

    } else {
        INFO_("client disconnected\n");
        rfcomm_server_close_client(handle->data);
    }
}

static void rfcomm_server_poll_server_data(uv_poll_t* handle, int status, int events)
{
    if (events & UV_READABLE) {
        if (status == 0) {
            INFO_("accept...\n");
            if (rfcomm_server_accept_client()) {
                ERROR_("accept a client fail\n");
            }

        } else {
            INFO_("poll status:%d\n", status);
        }
        return;
    }

fail:
    INFO_("server disconnected\n");
    rfcomm_server_close();
}

static int rfcomm_server_accept_client(void)
{
    int i, ret;
    struct sockaddr_rc rem_addr = { 0 };
    char buf[64] = { 0 };
    socklen_t opt = sizeof(rem_addr);

    bdaddr_t bt_mac;
    char bt_mac_str[18];
    ret = rfcomm_net_get_host_bt_addr(&bt_mac);
    if (ret) {
        ERROR_("get host mac fail\n");
        return -1;
    }
    ba2str(&bt_mac, bt_mac_str);

    client_handle_t* handle = (client_handle_t*)calloc(1, sizeof(client_handle_t));
    if (handle == NULL) {
        ERROR_("calloc handle fail\n");
        return -1;
    }

    for (i = 0; i < SERVER_SUPPORT_CLIENT_NUM; i++) {
        if (rfcomm_net_list_traversal(&client_list, rfcomm_server_check_by_index, i)) {
            handle->index = i;
            break;
        }
    }
    if (i == SERVER_SUPPORT_CLIENT_NUM) {
        ERROR_("find free index fail\n");
        return -1;
    }

    int client_fd = accept(g_server_service.rfcomm_fd, (struct sockaddr*)&rem_addr, &opt);
    handle->client_fd = client_fd;
    ba2str(&rem_addr.rc_bdaddr, buf);
    INFO_("accept from %s\n", buf);

    snprintf(buf, sizeof(buf), SERVER_TAP_IFNAME, handle->index);
    int tap_fd = rfcomm_net_tap_open(buf, bt_mac_str);
    if (tap_fd < 0) {
        ERROR_("open tap fail\n");
        return -1;
    }
    handle->tap_fd = tap_fd;

    ret = rfcomm_server_bridge_add_iface(buf, SERVER_BR_IFNAME);
    if (ret) {
        ERROR_("add iface to bridge fail\n");
        return -1;
    }

    uv_poll_t* client_poll_handle = rfcomm_net_uv_poll_start(g_server_service.loop,
        client_fd, UV_DISCONNECT | UV_READABLE,
        rfcomm_server_poll_client_data, handle);
    if (client_poll_handle == NULL) {
        ERROR_("poll client fail\n");
        return -1;
    }
    handle->client_poll_handle = client_poll_handle;

    uv_poll_t* tap_poll_handle = rfcomm_net_uv_poll_start(g_server_service.loop,
        tap_fd, UV_DISCONNECT | UV_READABLE,
        rfcomm_server_poll_tap_data, handle);
    if (tap_poll_handle == NULL) {
        ERROR_("poll tap fail\n");
        return -1;
    }
    handle->tap_poll_handle = tap_poll_handle;

    rfcomm_net_list_add_item(&client_list, (struct list_node*)handle);
    return 0;

fail:
    rfcomm_server_close_client((struct list_node*)handle);
    return -1;
}

static void rfcomm_server_close_client(struct list_node* handle)
{
    char buf[64] = { 0 };
    client_handle_t* client_handle = (client_handle_t*)handle;
    if (client_handle == NULL) {
        return;
    }

    if (client_handle->client_fd > 0) {
        close(client_handle->client_fd);
    }
    rfcomm_net_uv_poll_stop(client_handle->client_poll_handle);
    rfcomm_net_uv_poll_stop(client_handle->tap_poll_handle);

    snprintf(buf, sizeof(buf), SERVER_TAP_IFNAME, client_handle->index);
    rfcomm_server_bridge_del_iface(buf, SERVER_BR_IFNAME);
    rfcomm_net_tap_close(buf, client_handle->tap_fd);

    rfcomm_net_list_del_item((struct list_node*)client_handle, rfcomm_server_item_free);
}

static int rfcomm_server_spp_service_register(void)
{
    int ret = 0;

    uint32_t uuid_int[] = { 0x01110000, 0x00100000, 0x80000080, 0xFB349B5F };
    uint8_t* uuid_ptr = (uint8_t*)&uuid_int[0];
    uuid_ptr[2] = (SERVER_BT_UUID >> 8) & 0xFF;
    uuid_ptr[3] = SERVER_BT_UUID & 0xFF;

    uint8_t rfcomm_channel = SERVER_BT_CHANNEL;
    const char* service_name = "Rfcomm server";
    const char* service_dsc = "server of net proxy by rfcomm.";
    const char* service_prov = "YJ";

    uuid_t root_uuid, l2cap_uuid, rfcomm_uuid, svc_uuid;
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
    channel = sdp_data_alloc(SDP_UINT8, &rfcomm_channel);
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

    int err = 0;
    g_sdp_service.session = 0;

    // connect to the local SDP server, register the service record, and
    // disconnect
    g_sdp_service.session
        = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, SDP_RETRY_IF_BUSY);
    if (g_sdp_service.session == NULL) {
        sdp_record_free(g_sdp_service.rec);
        g_sdp_service.rec = NULL;
        ERROR_("sdp connect fail\n");
        ret = -1;
    }

    err = sdp_record_register(g_sdp_service.session, g_sdp_service.rec, 0);
    if (err == -1) {
        sdp_close(g_sdp_service.session);
        g_sdp_service.session = NULL;
        sdp_record_free(g_sdp_service.rec);
        g_sdp_service.rec = NULL;
        ERROR_("sdp register fail\n");
        ret = -2;
    }

    // cleanup
    sdp_data_free(channel);
    sdp_list_free(l2cap_list, 0);
    sdp_list_free(rfcomm_list, 0);
    sdp_list_free(root_list, 0);
    sdp_list_free(access_proto_list, 0);
    return ret;
}

static void rfcomm_server_spp_service_unregister(void)
{
    if (g_sdp_service.session && g_sdp_service.rec) {
        sdp_record_unregister(g_sdp_service.session, g_sdp_service.rec);
        sdp_close(g_sdp_service.session);
        g_sdp_service.session = NULL;
        g_sdp_service.rec = NULL;
    }

    /* double free */
    // sdp_record_free(g_sdp_service.rec);
}

static int rfcomm_server_create(void)
{
    int ret;
    struct sockaddr_rc loc_addr = { 0 };
    INFO_("create server\n");

    bdaddr_t bt_mac;
    char bt_mac_str[18];
    ret = rfcomm_net_get_host_bt_addr(&bt_mac);
    if (ret) {
        ERROR_("get host mac fail\n");
        goto fail;
    }
    ba2str(&bt_mac, bt_mac_str);

    rfcomm_net_list_init(&client_list);

    ret = rfcomm_server_spp_service_register();
    if (ret != 0) {
        ERROR_("register service fail\n");
        goto fail;
    }

    ret = rfcomm_server_bridge_create();
    if (ret != 0) {
        ERROR_("create bridge fail\n");
        goto fail;
    }

    ret = rfcomm_net_iface_up(SERVER_BR_IFNAME);
    if (ret != 0) {
        ERROR_("up bridge fail\n");
        goto fail;
    }

    rfcomm_net_iface_set_mac(SERVER_BR_IFNAME, bt_mac_str);
    rfcomm_net_iface_set_ip(SERVER_BR_IP, SERVER_BR_IFNAME);

    g_server_service.rfcomm_fd = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    loc_addr.rc_family = AF_BLUETOOTH;
    loc_addr.rc_bdaddr = *BDADDR_ANY;
    loc_addr.rc_channel = (uint8_t)SERVER_BT_CHANNEL;
    bind(g_server_service.rfcomm_fd, (struct sockaddr*)&loc_addr, sizeof(loc_addr));
    listen(g_server_service.rfcomm_fd, SERVER_SUPPORT_CLIENT_NUM);

    INFO_("listen...\n");
    g_server_service.server_poll_handle = rfcomm_net_uv_poll_start(g_server_service.loop,
        g_server_service.rfcomm_fd, UV_DISCONNECT | UV_READABLE,
        rfcomm_server_poll_server_data, NULL);

    return ret;

fail:
    rfcomm_server_close();
    return ret;
}

static int rfcomm_server_close(void)
{
    INFO_("close server\n");
    rfcomm_net_list_destroy(&client_list, rfcomm_server_close_client);
    rfcomm_net_uv_poll_stop(g_server_service.server_poll_handle);
    g_server_service.server_poll_handle = NULL;

    if (g_server_service.rfcomm_fd > 0) {
        close(g_server_service.rfcomm_fd);
        g_server_service.rfcomm_fd = -1;
    }

    rfcomm_server_bridge_remove();
    rfcomm_server_spp_service_unregister();
}

int main(int argc, char** argv)
{
    g_server_service.loop = uv_default_loop();

    rfcomm_net_command_start(g_server_service.loop, rfcomm_server_cmd_execute);

    uv_run(g_server_service.loop, UV_RUN_DEFAULT);

    return 0;
}

// gcc common.c server.c -lbluetooth -luv -o server
