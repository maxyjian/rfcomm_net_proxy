#include "common.h"

#define CLIENT_TAP_IFNAME "bt-net"
#define CLIENT_DEST_MAC "9C:BC:F0:EA:E9:15"
#define CLIENT_BT_CHANNEL 11
#define CLIENT_BT_UUID 0x1101

typedef struct {
    int tap_fd;
    int client_fd;
    uv_poll_t* tap_poll_handle;
    uv_poll_t* client_poll_handle;
    uv_loop_t* loop;
} client_service_t;

static client_service_t g_client_service = {
    .tap_fd = -1,
    .client_fd = -1,
};

static int rfcomm_client_connect(void);
static int rfcomm_client_close(void);
static void rfcomm_client_cmd_usage(void);

static int rfcomm_client_cmd_connect(int argc, char** argv)
{
    int ret = rfcomm_client_connect();
    if (ret) {
        ERROR_("connect fail\n");
    }
    return 0;
}

static int rfcomm_client_cmd_disconnect(int argc, char** argv)
{
    rfcomm_client_close();
    return 0;
}

static int rfcomm_client_cmd_help(int argc, char** argv)
{
    rfcomm_client_cmd_usage();
    return 0;
}

static rfcomm_net_command_t cmd_table[] = {
    { "connect", rfcomm_client_cmd_connect, "connect server" },
    { "disconnect", rfcomm_client_cmd_disconnect, "disconnect server" },
    { "help", rfcomm_client_cmd_help, "help for tools" },
};

static void rfcomm_client_cmd_usage(void)
{
    RAW_("Commands:\n");
    for (int i = 0; i < sizeof(cmd_table) / sizeof(cmd_table[0]); i++) {
        RAW_("\t%-4s\t%s\n", cmd_table[i].cmd, cmd_table[i].help);
    }
}

static int rfcomm_client_cmd_execute(int argc, char* argv[])
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
    rfcomm_client_cmd_usage();

    return -1;
}

static void rfcomm_client_poll_tap_data(uv_poll_t* handle, int status, int events)
{
    uint8_t buf[TAP_MAX_PKT_WRITE_LEN];

    if (events & UV_READABLE) {
        if (status == 0) {
            int ret = read(g_client_service.tap_fd, buf,
                TAP_MAX_PKT_WRITE_LEN);
            if (ret > 0) {
                rfcomm_net_protocol_send(g_client_service.client_fd, buf, ret);
            }

            INFO_("poll ret:%d\n", ret);
            return;
        } else {
            INFO_("poll status:%d\n", status);
            return;
        }

    } else {
        INFO_("poll disconnected\n");
        rfcomm_client_close();
    }
}

static void rfcomm_client_poll_client_data(uv_poll_t* handle, int status, int events)
{
    uint8_t buf[TAP_MAX_PKT_WRITE_LEN];

    if (events & UV_READABLE) {
        if (status == 0) {
            int ret = read(g_client_service.client_fd, buf,
                TAP_MAX_PKT_WRITE_LEN);
            if (ret > 0) {
                rfcomm_net_protocol_receive(g_client_service.tap_fd, buf, ret);
            }

            INFO_("poll ret:%d\n", ret);
            return;
        } else {
            INFO_("poll status:%d\n", status);
            return;
        }

    } else {
        INFO_("client disconnected\n");
        rfcomm_client_close();
    }
}

static int rfcomm_client_connect(void)
{
    bdaddr_t bt_mac;
    char bt_mac_str[18];
    int ret = rfcomm_net_get_host_bt_addr(&bt_mac);
    if (ret) {
        ERROR_("get host mac fail\n");
        goto fail;
    }
    ba2str(&bt_mac, bt_mac_str);

    INFO_("client connect\n");
    g_client_service.client_fd = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (g_client_service.client_fd < 0) {
        ERROR_("create socket fail:%d\n", g_client_service.client_fd);
        goto fail;
    }

    struct sockaddr_rc addr = { 0 };
    addr.rc_family = AF_BLUETOOTH;
    addr.rc_channel = (uint8_t)CLIENT_BT_CHANNEL;
    str2ba(CLIENT_DEST_MAC, &addr.rc_bdaddr);

    int status = connect(g_client_service.client_fd, (struct sockaddr*)&addr, sizeof(addr));
    if (status) {
        ERROR_("connect fail:%d\n", status);
        goto fail;
    }
    INFO_("connect success\n");

    g_client_service.client_poll_handle = rfcomm_net_uv_poll_start(g_client_service.loop,
        g_client_service.client_fd, UV_DISCONNECT | UV_READABLE,
        rfcomm_client_poll_client_data, NULL);
    if (g_client_service.client_poll_handle == NULL) {
        ERROR_("poll client fail\n");
        goto fail;
    }

    g_client_service.tap_fd = rfcomm_net_tap_open(CLIENT_TAP_IFNAME, bt_mac_str);
    if (g_client_service.tap_fd < 0) {
        ERROR_("open tap fail\n");
        goto fail;
    }

    g_client_service.tap_poll_handle = rfcomm_net_uv_poll_start(g_client_service.loop,
        g_client_service.tap_fd, UV_DISCONNECT | UV_READABLE,
        rfcomm_client_poll_tap_data, NULL);
    if (g_client_service.tap_poll_handle == NULL) {
        ERROR_("poll tap fail\n");
        goto fail;
    }

    return 0;

fail:
    rfcomm_client_close();
    return -1;
}

static int rfcomm_client_close(void)
{
    INFO_("client close\n");

    rfcomm_net_uv_poll_stop(g_client_service.client_poll_handle);
    g_client_service.client_poll_handle = NULL;
    rfcomm_net_uv_poll_stop(g_client_service.tap_poll_handle);
    g_client_service.tap_poll_handle = NULL;

    if (g_client_service.client_fd) {
        close(g_client_service.client_fd);
        g_client_service.client_fd = -1;
    }

    rfcomm_net_tap_close(CLIENT_TAP_IFNAME, g_client_service.tap_fd);
    g_client_service.tap_fd = -1;
}

int main(int argc, char** argv)
{
    g_client_service.loop = uv_default_loop();

    rfcomm_net_command_start(g_client_service.loop, rfcomm_client_cmd_execute);

    uv_run(g_client_service.loop, UV_RUN_DEFAULT);

    return 0;
}

// gcc common.c client.c -lbluetooth -luv -o client
