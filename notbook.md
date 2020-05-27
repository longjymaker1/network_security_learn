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
### ping扫描
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

#### ICMP Echo包解析
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

### ARP扫描
直连ping扫描效果很差，因为个人电脑的防火墙默认禁用ping。但是对ARP扫描是很实用的，每个设备都会对ARP扫描进行回应

#### ARP协议
##### ARP出现原因
ARP协议是“Address Resolution Protocol”（地址解析协议）的缩写。其作用是在以太网环境中，
数据的传输所依懒的是MAC地址而非IP地址，而将已知IP地址转换为MAC地址的工作是由ARP协议来完成的。

在局域网中，网络中实际传输的是“帧”，帧里面是有目标主机的MAC地址的。
在以太网中，一个主机和另一个主机进行直接通信，必须要知道目标主机的MAC地址。
但这个目标MAC地址是如何获得的呢？它就是通过地址解析协议获得的。所谓“地址解析”就是主机在发送帧前将目标IP地址转换成目标MAC地址的过程。
ARP协议的基本功能就是通过目标设备的IP地址，查询目标设备的MAC地址，以保证通信的顺利进行。
##### ARP映射方式
###### 1.静态映射
静态映射的意思是要手动创建一张ARP表，把逻辑（IP）地址和物理地址关联起来。这个ARP表储存在网络中的每一台机器上。
例如，知道其机器的IP地址但不知道其物理地址的机器就可以通过查ARP表找出对应的物理地址。
这样做有一定的局限性，因为物理地址可能发生变化：
1. 机器可能更换NIC（网络适配器），结果变成一个新的物理地址
2. 在某些局域网中，每当计算机加电时，他的物理地址都要改变一次
3. 移动电脑可以从一个物理网络转移到另一个物理网络，这样会时物理地址改变

要避免这些问题出现，必须定期维护更新ARP表，此类比较麻烦而且会影响网络性能

###### 2.动态映射
动态映射时，每次只要机器知道另一台机器的逻辑（IP）地址，就可以使用协议找出相对应的物理地址。
已经设计出的实现了动态映射协议的有ARP和RARP两种。ARP把逻辑（IP）地址映射为物理地址。RARP把物理地址映射为逻辑（IP）地址

##### ARP原理及流程
在任何时候，一台主机有IP数据报文发送给另一台主机，它都要知道接收方的逻辑（IP）地址。
但是IP地址必须封装成帧才能通过物理网络。这就意味着发送方必须有接收方的物理（MAC）地址，因此需要完成逻辑地址到物理地址的映射。
而ARP协议可以接收来自IP协议的逻辑地址，将其映射为相应的物理地址，然后把物理地址递交给数据链路层
###### 1.ARP请求
任何时候，当主机需要找出这个网络中的另一个主机的物理地址时，它就可以发送一个ARP请求报文，
这个报文包好了发送方的MAC地址和IP地址以及接收方的IP地址。
因为发送方不知道接收方的物理地址，所以这个查询分组会在网络层中进行广播
###### 2.ARP响应
局域网中的每一台主机都会接受并处理这个ARP请求报文，然后进行验证，查看接收方的IP地址是不是自己的地址，
只有验证成功的主机才会返回一个ARP响应报文，这个响应报文包含接收方的IP地址和物理地址。
这个报文利用收到的ARP请求报文中的请求方物理地址以单播的方式直接发送给ARP请求报文的请求方

##### ARP协议报文字段抓包解析
##### 报文格式

|----------硬件类型----------|----------协议类型----------|

|--硬件长度--|--协议长度--||--操作码(请求为1, 响应为2)--|

|-------------------源硬件地址---------------------|

|-------------------源逻辑地址---------------------|

|------------------目的硬件地址---------------------|

|------------------目的逻辑地址---------------------|

* `硬件类型`：16位字段，用来定义运行ARP的网络类型。每个局域网基于其类型被指派一个整数。例如：以太网的类型为1。ARP可用在任何物理网络上。
* `协议类型`：16位字段，用来定义使用的协议。例如：对IPv4协议这个字段是0800。ARP可用于任何高层协议
* `硬件长度`：8位字段，用来定义物理地址的长度，以字节为单位。例如：对于以太网的值为6
* `协议长度`：8位字段，用来定义逻辑地址的长度，以字节为单位。例如：对于IPv4协议的值为4
* `操作码`：16位字段，用来定义报文的类型。已定义的分组类型有两种：ARP请求（1），ARP响应（2）
* `源硬件地址`：这是一个可变长度字段，用来定义发送方的物理地址。例如：对于以太网这个字段的长度是6字节
* `源逻辑地址`：这是一个可变长度字段，用来定义发送方的逻辑（IP）地址。例如：对于IP协议这个字段的长度是4字节
* `目的硬件地址`：这是一个可变长度字段，用来定义目标的物理地址，例如，对以太网来说这个字段位6字节。对于ARP请求报文，这个字段为全0，因为发送方并不知道目标的硬件地址
* `目的逻辑地址`：这是一个可变长度字段，用来定义目标的逻辑（IP）地址，对于IPv4协议这个字段的长度为4个字节


#### ARP包解析
ARP针对的是二层广播。不能跨网络

请求包
```bash
>>> a=Ether()/ARP()
>>> a.show()
###[ Ethernet ]###
  dst= ff:ff:ff:ff:ff:ff
  src= 00:ff:6c:95:c6:e9
  type= ARP
###[ ARP ]###
     hwtype= 0x1
     ptype= IPv4
     hwlen= None
     plen= None
     op= who-has  # 1
     hwsrc= 00:ff:6c:95:c6:e9  # 原mac
     psrc= 192.168.31.163  # 原ip
     hwdst= 00:00:00:00:00:00  # 目的mac
     pdst= 0.0.0.0  # 目的ip
```
