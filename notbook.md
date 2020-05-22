# 网络安全

## 扫描
了解网络和主机情况是攻击的第一步，使用ping对网络进行扫描得到活动主机清单

* scapy, http以下都可以使用scapy实现

### 工具 - scapy铸造包
```shell script
>>> a = Ether()/IP()/TCP()
>>> a.show()
###[ Ethernet ]###  # 以太网都不，如果是默认铸造就是一个广播，
  dst= ff:ff:ff:ff:ff:ff
  src= 00:ff:c1:bc:7b:5d  # 默认会写接口的mac地址
  type= IPv4
###[ IP ]###
     version= 4
     ihl= None
     tos= 0x0
     len= None
     id= 1
     flags=
     frag= 0
     ttl= 64
     proto= tcp
     chksum= None
     src= 172.31.93.252  # 默认填自己的ip地址
     dst= 127.0.0.1  # 目的地地址
     \options\
###[ TCP ]###
        sport= ftp_data
        dport= http
        seq= 0
        ack= 0
        dataofs= None
        reserved= 0
        flags= S
        window= 8192
        chksum= None  # 自动计算校验核
        urgptr= 0
        options= []
```
铸造一个ping包
```shell script
>>> b = IP(dst="172.31.93.1")/ICMP()/b'welcome to long'
>>> b.show()
###[ IP ]###
  version= 4
  ihl= None
  tos= 0x0
  len= None
  id= 1
  flags=
  frag= 0
  ttl= 64
  proto= icmp
  chksum= None
  src= 172.31.93.252
  dst= 172.31.93.1
  \options\
###[ ICMP ]###
     type= echo-request
     code= 0
     chksum= None
     id= 0x0
     seq= 0x0
###[ Raw ]###
        load= 'welcome to long'

# 发送包 sr1发送并且等待1个包的回应，并赋给ping变量
>>> ping = sr1(b)
Begin emission:
Finished sending 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets

>>> ping.show()
###[ IP ]###
  version= 4
  ihl= 5
  tos= 0x0
  len= 43
  id= 1
  flags=
  frag= 0
  ttl= 254
  proto= icmp
  chksum= 0xa994
  src= 172.31.93.1
  dst= 172.31.93.252
  \options\
###[ ICMP ]###
     type= echo-reply
     code= 0
     chksum= 0xdc5e
     id= 0x0
     seq= 0x0
###[ Raw ]###
        load= 'welcome to long'

# 提取ping包的ICMP, 并转化为字典
>>> ping.getlayer(ICMP).fields
{'type': 0,
 'code': 0,
 'chksum': 56414,
 'id': 0,
 'seq': 0,
 'ts_ori': None,
 'ts_rx': None,
 'ts_tx': None,
 'gw': None,
 'ptr': None,
 'reserved': None,
 'length': None,
 'addr_mask': None,
 'nexthopmtu': None,
 'unused': None}
```
* `sr()`, 发送三层数据包，等待接收一个或多个回应
* `sr1()`，发送三层数据包，是发一个收一个回应
* `srp()`, 发二层数据包，并且等待回应
* `send()`, 进进发送三层数据包，系统自动处理路由和二层信息
* `sendp()`, 发送二层数据包

### ICMP Echo包解析
```shell script
###[ IP ]###
  version= 4  # 4：表示为IPV4；6：表示为IPV6
  ihl= None  # 首部长度，如果不带Option字段，则为20，最长为60，该值限制了记录路由选项。以4字节为一个单位
  tos= 0x0  # 服务类型。只有在有QoS差分服务要求时这个字段才起作用
  len= None  # 总长度，整个IP数据报的长度，包括首部和数据之和，单位为字节，最长65535，总长度必须不超过最大传输单元MTU
  id= 1  # 标识，主机每发一个报文，加1，分片重组时会用到该字段
  flags=  # 标志位：Bit 0: 保留位，必须为0。Bit 1: DF（Don’t Fragment），能否分片位，
          # 0表示可以分片，
          # 1表示不能分片。
          # Bit 2: MF（More Fragment），表示是否该报文为最后一片，0表示最后一片，1代表后面还有
  frag= 0  # 片偏移：分片重组时会用到该字段。表示较长的分组在分片后，某片在原分组中的相对位置。以8个字节为偏移单位
  ttl= 64  # 生存时间：可经过的最多路由数，即数据包在网络中可通过的路由器数的最大值
  proto= icmp  # 协议：下一层协议。指出此数据包携带的数据使用何种协议，以便目的主机的IP层将数据部分上交给哪个进程处理
  chksum= None  # 首部检验和，只检验数据包的首部，不检验数据部分。这里不采用CRC检验码，而采用简单的计算方法
  src= 172.31.93.252  # 源IP地址
  dst= 172.31.93.1  # 目的IP地址
  \options\  # 选项字段，用来支持排错，测量以及安全等措施，内容丰富（请参见下表）。
             # 选项字段长度可变，从1字节到40字节不等，取决于所选项的功能
###[ ICMP ]###
     type= 8  # ICMP 的type和code要结合看 type=8, code=0为Echo request——回显请求（Ping请求）
     code= 0
     chksum= None
     id= 0x0  # 进程位
     seq= 0x0  # 包的序列号位
###[ Raw ]###
        load= 'welcome to long'
```

* 1 `type=0, code=0`, Echo Reply——回显应答（Ping应答）
* 2 `type=3, code=0`, Network Unreachable——网络不可达
* 3 `type=3, code=1`, Host Unreachable——主机不可达
* 4 `type=3, code=2`, Protocol Unreachable——协议不可达
* 5 `type=3, code=3`, Port Unreachable——端口不可达
* 6 `type=3, code=4`, Fragmentation needed but no frag. bit set——需要进行分片但设置不分片比特
* 7 `type=3, code=5`, Source routing failed——源站选路失败
* 8 `type=3, code=6`, Destination network unknown——目的网络未知
* 9 `type=3, code=7`, Destination host unknown——目的主机未知
* 10 `type=3, code=8`, Source host isolated (obsolete)——源主机被隔离（作废不用）
* 11 `type=3, code=9`, Destination network administratively prohibited——目的网络被强制禁止
* 12 `type=3, code=10`, Destination host administratively prohibited——目的主机被强制禁止
* 13 `type=3, code=11`, Network unreachable for TOS——由于服务类型TOS，网络不可达
* 14 `type=3, code=12`, Host unreachable for TOS——由于服务类型TOS，主机不可达
* 15 `type=3, code=13`, Communication administratively prohibited by filtering——由于过滤，通信被强制禁止
* 16 `type=3, code=14`, Host precedence violation——主机越权
* 17 `type=3, code=15`, Precedence cutoff in effect——优先中止生效
* 18 `type=4, code=0`, Source quench——源端被关闭（基本流控制）
* 19 `type=5, code=0`, Redirect for network——对网络重定向
* 20 `type=5, code=1`, Redirect for host——对主机重定向
* 21 `type=5, code=2`, Redirect for TOS and network——对服务类型和网络重定向
* 22 `type=5, code=3`, Redirect for TOS and host——对服务类型和主机重定向
* 23 `type=8, code=0`, Echo request——回显请求（Ping请求）
* 24 `type=9, code=0`, Router advertisement——路由器通告
* 25 `type=10, code=0`, Route solicitation——路由器请求
* 26 `type=11, code=0`, TTL equals 0 during transit——传输期间生存时间为0
* 27 `type=11, code=1`, TTL equals 0 during reassembly——在数据报组装期间生存时间为0
* 28 `type=12, code=0`, IP header bad (catchall error)——坏的IP首部（包括各种差错）
* 29 `type=12, code=1`, Required options missing——缺少必需的选项
* 30 `type=13, code=0`, Timestamp request (obsolete)——时间戳请求（作废不用）
* 31 `type=14 `, Timestamp reply (obsolete)——时间戳应答（作废不用）
* 32 `type=15, code=0`, Information request (obsolete)——信息请求（作废不用）
* 33 `type=16, code=0`, Information reply (obsolete)——信息应答（作废不用）
* 34 `type=17, code=0`, Address mask request——地址掩码请求
* 35 `type=18, code=0`, Address mask reply——地址掩码应答


