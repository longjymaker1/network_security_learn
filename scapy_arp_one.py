import logging
from scapy.all import *
from scapy.layers.inet import IP, ICMP, Ether
from scapy.layers.l2 import ARP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def arp_one(ip_address, queue=None, ifname='eno33554944'):
    # arp 针对的是二层广播，而且还要收响应所以用srp
    result_raw = srp(Ether(dst='FF:FF:FF:FF:FF:FF') / ARP(op=1, hwdst="00:00:00:00:00:00", pdst=ip_address),
                     timeout=1,
                     # iface=ifname,
                     verbose=False)
    try:
        result_list = result_raw[0].rse  # 把响应的数据包对，产生为清单
        # [0]为第一组响应数据
        # [1]接收到的数据包, [0]为发送的数据包
        # [1]ARP头部字段中的['hwsrc']字段, 作为返回值返回
        if queue is None:
            return result_list[0][1].getlayer(ARP).fields['hwsrc']
        else:
            queue.put((ip_address, result_list[0][1].getlayer(ARP).fields['hwsrc']))
    except Exception as e:
        return e


if __name__ == '__main__':
    import sys
    print(arp_one('192.168.31.163'))