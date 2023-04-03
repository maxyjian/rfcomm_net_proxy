# rfcomm network proxy
Use bluetooth rfcomm to enable the linux device to support the network.

## build environment
### install dependencies
```
sudo apt-get install libbluetooth-dev
sudo apt-get install libuv1-dev
sudo apt install -y dnsmasq  
```

### support dhcp
Add the following content to /etc/dnsmasq.conf
```
interface=bt-bridge
server=114.114.114.114
listen-address=192.168.10.1
dhcp-range=192.168.10.2,192.168.10.254,12h
```
Add a new file /etc/netplan/01-dhcp.yaml, the content is as follows In a word, it is to configure the internal network card as a static IP:
```
network:
  ethernets:
    bt-bridge:
      addresses:
        - 192.168.10.1/24
  version: 2
```
Restart the network
```
sudo netplan --debug apply
sudo systemctl start dnsmasq
```
Masquerade the data packet whose source address is 192.168.10.0\24, and replace it with the IP address of eno1, which is the egress address of the router’s external network:
```
iptables -t nat -A POSTROUTING -s 192.168.10.1/24 -o eno1 -j MASQUERADE
```

## compile and run

### server
```
$ gcc common.c server.c -lbluetooth -luv -o server
$ sudo ./server
rfcomm_net> enable
```

### client
```
$ gcc common.c client.c -lbluetooth -luv -o client
$ sudo ./client
rfcomm_net> connect
```

## TODO
1、Can tun be used?
2、Make the transport protocol more reliable.
