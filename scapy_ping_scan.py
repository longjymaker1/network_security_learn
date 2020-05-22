import logging
import ipaddress
import sys
import time
import multiprocessing
from scapy_ping_one import ping_one

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def ping_scan(network):
    """
    ping扫描网段
    :param network: 一个网段 172.31.93.0/24
    :return: None
    """
    print(network)
    net = ipaddress.ip_network(network)  # 传入一个网路，提取网络里面的ip地址
    ip_processes = {}
    for ip in net:
        ip_addr = str(ip)  # ip地址转化为字符串
        ping_ones = multiprocessing.Process(target=ping_one, args=(ip_addr,))
        ping_ones.start()
        ip_processes[ip_addr] = ping_ones  # 产生IP与进程对应的字典
    ip_list = []
    for ip, process in ip_processes.items():
        if process.exitcode == 3:
            ip_list.append(ip)
        else:
            process.terminate()
    return sorted(ip_list)


if __name__ == '__main__':
    t0 = time.time()
    active_ip = ping_scan('172.31.93.0/24')
    print("活动的ip地址")
    for ip in active_ip:
        print(ip)
    t1 = time.time()
    print(t1-t0)
    print(len(active_ip))