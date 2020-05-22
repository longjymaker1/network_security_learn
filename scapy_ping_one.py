import logging
from scapy.all import *
from random import randint
from scapy.layers.inet import IP, ICMP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def ping_one(host):
    """
    铸造并发送ping包
    :param host: 目标地址
    :return: None
    """
    id_ip = randint(1, 65535)  # 随机生成ip ID位
    id_ping = randint(1, 65535)  # 随机生成ping ID位
    seq_ping = randint(1, 65535)  # 随机生成ping序列号位
    # 构造ping数据包
    packet = IP(dst=host, ttl=128, id=id_ip)/ICMP(id=id_ping, seq=seq_ping)/b'long'
    ping = sr1(packet, timeout=2, verbose=False)  # 获取响应信息, 超时为2秒, 关闭详细信息
    # ping.show()
    if ping:  # 如果有相应信息
        os._exit(3)  # 退出码为3


if __name__ == '__main__':
    ping0 = ping_one('172.31.93.1')
    # print(sys.argv[0])
