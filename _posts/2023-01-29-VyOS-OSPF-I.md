---
title: VyOS - OSPF Basic Network
author: fwinsnes
date: 2023-01-01 18:17:00 +0800
categories: [Computer Networking]
tags: [VyOS, Networking, Routing, OSPF]
---

The following OSPF Network will be dissected within the length of this post:

#### Diagram

![](/assets/img/Networking/VyOS/routing/OSPF/VyOS-OSPF-I-Diagram.png)

Network consists of 5 VyOS-powered routers, from which 4 connect to a central switch to which send all OSPF-related communication. 

R4, will be the exiting leg of the network into EDGE-RT, which will be the Autonomous System Border Router (ASBR) and redistribute the access towards the Internet within the OSPF Network.

All other Routers will function as well for ABR Capabilities, connecting their respective within the backbone (area 0). 

OSPF Selects a Designated Router (DR) and a Backup Designated Router (BDR), this is determined by the protocol by the following list, from up to down, if the former is not found, it will check for the following, the Neighbor which has the largest value, becomes the DR, with the Neighbor that has the largest value, behind the DR, becomes the BDR:

1. OSPF Priority Value
2. Loopback IP Address
3. Interface IP Address

The following Loopbacks will be assigned

+ R1 - 172.16.0.1
+ R2 - 172.16.0.2
+ R3 - 172.16.0.3
+ R4 - 172.16.0.4
+ EDGE-RT - 172.16.0.254

Since R4 will have the highest Loopback IP Address within the Backbone area, such will become the DR, whereas R3, will become the BDR, and R1/R2 going to DROther state.

Due to the Network being a “Broadcast” type, second timers will be 10 Hello, 40 Wait, 40 Dead, and DR/BDR Selections will be performed.

#### Configuration


```term
vyos@R1:~$ show configuration commands | grep -vE 'ntp|syslog|login|conntrack|config-management|console|hw-id'
set interfaces ethernet eth0 address '10.10.11.1/29'
set interfaces ethernet eth1 address '10.10.10.1/29'
set interfaces loopback lo address '172.16.0.1/32'
set protocols ospf area 0 network '10.10.11.0/29'
set protocols ospf area 0 network '172.16.0.1/32'
set protocols ospf area 1 network '10.10.10.0/29'
set service ssh port '22'
set system host-name 'R1'
vyos@R1:~$ 
```

```term
vyos@R2:~$ show configuration commands | grep -vE 'ntp|syslog|login|conntrack|config-management|console|hw-id'
set interfaces ethernet eth0 address '10.10.11.2/29'
set interfaces ethernet eth1 address '10.10.10.9/29'
set interfaces loopback lo address '172.16.0.2/32'
set protocols ospf area 0 network '10.10.11.0/29'
set protocols ospf area 0 network '172.16.0.2/32'
set protocols ospf area 2 network '10.10.10.8/29'
set service ssh port '22'
set system host-name 'R2'
vyos@R2:~$
```

```term
vyos@R3:~$ show configuration commands | grep -vE 'ntp|syslog|login|conntrack|config-management|console|hw-id'
set interfaces ethernet eth0 address '10.10.11.3/29'
set interfaces ethernet eth1 address '10.10.11.14/30'
set interfaces ethernet eth1 address '10.10.10.17/29'
set interfaces ethernet eth2 address '10.10.11.10/30'
set interfaces loopback lo address '172.16.0.3/32'
set protocols ospf area 0 network '10.10.11.0/29'
set protocols ospf area 0 network '172.16.0.3/32'
set protocols ospf area 3 network '10.10.10.16/29'
set service ssh port '22'
set system host-name 'R3'
vyos@R3:~$
```

```term
vyos@R4:~$ show configuration commands | grep -vE 'ntp|syslog|login|conntrack|config-management|console|hw-id'
set interfaces ethernet eth0 address '10.10.254.2/30'
set interfaces ethernet eth1 address '10.10.11.4/29'
set interfaces loopback lo address '172.16.0.4/32'
set protocols ospf area 0 network '172.16.0.0/32'
set protocols ospf area 0 network '10.10.11.0/29'
set protocols ospf area 100 network '10.10.254.0/30'
set service ssh port '22'
set system host-name 'R4'
vyos@R4:~$
```

```term
vyos@IGW-RT:~$ show configuration commands | grep -vE 'ntp|syslog|login|conntrack|config-management|console|hw-id'
set firewall group address-group Allowed-Networks-Towards-Internet address '10.10.10.0-10.10.10.32'
set firewall group address-group Allowed-Networks-Towards-Internet address '10.10.11.0-10.10.11.16'
set firewall group address-group Allowed-Networks-Towards-Internet address '10.10.254.0-10.10.254.2'
set interfaces ethernet eth0 address '10.11.10.200/24'
set interfaces ethernet eth1 address '10.10.254.1/30'
set interfaces loopback lo address '172.16.0.254/32'
set nat source rule 1 destination address '0.0.0.0/0'
set nat source rule 1 outbound-interface 'eth0'
set nat source rule 1 source group address-group 'Allowed-Networks-Towards-Internet'
set nat source rule 1 translation address 'masquerade'
set protocols ospf area 100 network '10.10.254.0/30'
set protocols ospf area 100 network '10.11.10.0/24'
set protocols ospf default-information originate
set protocols ospf interface eth0 passive disable
set protocols static route 0.0.0.0/0 next-hop 10.11.10.1
set service ssh port '22'
set system host-name 'IGW-RT'
vyos@IGW-RT:~$
```

#### Neighbors

We can see the neighbour adjacencies coming up

+ R1

```term
vyos@R1:~$ show ip ospf neighbor 

Neighbor ID     Pri State           Up Time         Dead Time Address         Interface                        RXmtL RqstL DBsmL
172.16.0.2        1 2-Way/DROther   1h53m09s          31.114s 10.10.11.2      eth0:10.10.11.1                      0     0     0
172.16.0.3        1 Full/Backup     1h53m08s          31.870s 10.10.11.3      eth0:10.10.11.1                      0     0     0
172.16.0.4        1 Full/DR         1h53m03s          34.132s 10.10.11.4      eth0:10.10.11.1                      0     0     0

vyos@R1:~$ 
```

+ R2

```term
vyos@R2:~$ show ip ospf neighbor 

Neighbor ID     Pri State           Up Time         Dead Time Address         Interface                        RXmtL RqstL DBsmL
172.16.0.1        1 2-Way/DROther   1h53m21s          38.623s 10.10.11.1      eth0:10.10.11.2                      0     0     0
172.16.0.3        1 Full/Backup     1h53m26s          36.363s 10.10.11.3      eth0:10.10.11.2                      0     0     0
172.16.0.4        1 Full/DR         1h53m32s          38.623s 10.10.11.4      eth0:10.10.11.2                      0     0     0

vyos@R2:~$ 
```

+ R3

```term
vyos@R3:~$ show ip ospf neighbor 

Neighbor ID     Pri State           Up Time         Dead Time Address         Interface                        RXmtL RqstL DBsmL
172.16.0.1        1 Full/DROther    1h53m34s          38.474s 10.10.11.1      eth0:10.10.11.3                      0     0     0
172.16.0.2        1 Full/DROther    1h53m41s          35.465s 10.10.11.2      eth0:10.10.11.3                      0     0     0
172.16.0.4        1 Full/DR         1h53m48s          38.474s 10.10.11.4      eth0:10.10.11.3                      0     0     0

vyos@R3:~$ 
```

+ R4

```term
vyos@R4:~$ show ip ospf neighbor 

Neighbor ID     Pri State           Up Time         Dead Time Address         Interface                        RXmtL RqstL DBsmL
172.16.0.1        1 Full/DROther    1h53m46s          36.141s 10.10.11.1      eth1:10.10.11.4                      0     0     0
172.16.0.2        1 Full/DROther    1h54m00s          33.131s 10.10.11.2      eth1:10.10.11.4                      0     0     0
172.16.0.3        1 Full/Backup     1h54m00s          33.879s 10.10.11.3      eth1:10.10.11.4                      0     0     0
172.16.0.254      1 Full/DR         1h54m25s          34.790s 10.10.254.1     eth0:10.10.254.2                     0     0     0

vyos@R4:~$ 
```

+ EDGE-RT

```term
vyos@EDGE-RT:~$ show ip ospf neighbor 

Neighbor ID     Pri State           Up Time         Dead Time Address         Interface                        RXmtL RqstL DBsmL
172.16.0.4        1 Full/Backup     1h54m36s          35.381s 10.10.254.2     eth1:10.10.254.1                     0     0     0

vyos@EDGE-RT:~$ 
```
Within EDGE-R1, we can see as well Inter-Zone routes which have been advertised.

```term
vyos@EDGE-RT:~$ show ip route 
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

S>* 0.0.0.0/0 [1/0] via 10.11.10.1, eth0, weight 1, 02:17:47
O>* 10.10.10.0/29 [110/3] via 10.10.254.2, eth1, weight 1, 01:55:08
O>* 10.10.10.8/29 [110/3] via 10.10.254.2, eth1, weight 1, 01:55:31
O>* 10.10.10.16/29 [110/3] via 10.10.254.2, eth1, weight 1, 01:55:38
O>* 10.10.11.0/29 [110/2] via 10.10.254.2, eth1, weight 1, 01:55:43
O   10.10.254.0/30 [110/1] is directly connected, eth1, weight 1, 01:56:10
C>* 10.10.254.0/30 is directly connected, eth1, 01:56:43
O>* 172.16.0.1/32 [110/2] via 10.10.254.2, eth1, weight 1, 01:55:08
O>* 172.16.0.2/32 [110/2] via 10.10.254.2, eth1, weight 1, 01:55:31
O>* 172.16.0.3/32 [110/2] via 10.10.254.2, eth1, weight 1, 01:55:43
C>* 172.16.0.254/32 is directly connected, lo, 02:17:50
O   10.11.10.0/24 [110/1] is directly connected, eth0, weight 1, 02:17:46
C>* 10.11.10.0/24 is directly connected, eth0, 02:17:50
vyos@EDGE-RT:~$ show ip ospf route 
============ OSPF network routing table ============
N IA 10.10.10.0/29         [3] area: 0.0.0.100
                           via 10.10.254.2, eth1
N IA 10.10.10.8/29         [3] area: 0.0.0.100
                           via 10.10.254.2, eth1
N IA 10.10.10.16/29        [3] area: 0.0.0.100
                           via 10.10.254.2, eth1
N IA 10.10.11.0/29         [2] area: 0.0.0.100
                           via 10.10.254.2, eth1
N    10.10.254.0/30        [1] area: 0.0.0.100
                           directly attached to eth1
N IA 172.16.0.1/32         [2] area: 0.0.0.100
                           via 10.10.254.2, eth1
N IA 172.16.0.2/32         [2] area: 0.0.0.100
                           via 10.10.254.2, eth1
N IA 172.16.0.3/32         [2] area: 0.0.0.100
                           via 10.10.254.2, eth1
N    10.11.10.0/24      [1] area: 0.0.0.100
                           directly attached to eth0

============ OSPF router routing table =============
R    172.16.0.4            [1] area: 0.0.0.100, ABR
                           via 10.10.254.2, eth1

============ OSPF external routing table ===========

vyos@EDGE-RT:~$ 
```


The 'default-information originate' command will redistribute the static route towards the Internet, issued by EDGE-RT into the OSPF network.

```term
vyos@R1:~$ show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

O>* 0.0.0.0/0 [110/10] via 10.10.11.4, eth0, weight 1, 01:54:27
O   10.10.10.0/29 [110/1] is directly connected, eth1, weight 1, 01:54:42
C>* 10.10.10.0/29 is directly connected, eth3, 02:22:01
O>* 10.10.10.8/29 [110/2] via 10.10.11.2, eth0, weight 1, 01:54:28
O>* 10.10.10.16/29 [110/2] via 10.10.11.3, eth0, weight 1, 01:54:28
O   10.10.11.0/29 [110/1] is directly connected, eth0, weight 1, 01:54:28
C>* 10.10.11.0/29 is directly connected, eth0, 02:22:02
O>* 10.10.254.0/30 [110/2] via 10.10.11.4, eth0, weight 1, 01:54:28
O   172.16.0.1/32 [110/0] is directly connected, lo, weight 1, 01:54:42
C>* 172.16.0.1/32 is directly connected, lo, 02:22:02
O>* 172.16.0.2/32 [110/1] via 10.10.11.2, eth0, weight 1, 01:54:28
O>* 172.16.0.3/32 [110/1] via 10.10.11.3, eth0, weight 1, 01:54:28
O>* 10.11.10.0/24 [110/3] via 10.10.11.4, eth0, weight 1, 01:54:28

vyos@R1:~$ show ip ospf route 
============ OSPF network routing table ============
N    10.10.10.0/29         [1] area: 0.0.0.1
                           directly attached to eth1
N IA 10.10.10.8/29         [2] area: 0.0.0.0
                           via 10.10.11.2, eth0
N IA 10.10.10.16/29        [2] area: 0.0.0.0
                           via 10.10.11.3, eth0
N    10.10.11.0/29         [1] area: 0.0.0.0
                           directly attached to eth0
N IA 10.10.254.0/30        [2] area: 0.0.0.0
                           via 10.10.11.4, eth0
N    172.16.0.1/32         [0] area: 0.0.0.0
                           directly attached to lo
N    172.16.0.2/32         [1] area: 0.0.0.0
                           via 10.10.11.2, eth0
N    172.16.0.3/32         [1] area: 0.0.0.0
                           via 10.10.11.3, eth0
N IA 10.11.10.0/24      [3] area: 0.0.0.0
                           via 10.10.11.4, eth0

============ OSPF router routing table =============
R    172.16.0.2            [1] area: 0.0.0.0, ABR
                           via 10.10.11.2, eth0
R    172.16.0.3            [1] area: 0.0.0.0, ABR
                           via 10.10.11.3, eth0
R    172.16.0.4            [1] area: 0.0.0.0, ABR
                           via 10.10.11.4, eth0
R    172.16.0.254       IA [2] area: 0.0.0.0, ASBR
                           via 10.10.11.4, eth0

============ OSPF external routing table ===========
N E2 0.0.0.0/0             [3/10] tag: 0
                           via 10.10.11.4, eth0

vyos@R1:~$ 
```

#### Traces 


```term
PC1> trace 10.10.10.18 -P 6
trace to 10.10.10.18, 8 hops max (TCP), press Ctrl+C to stop
 1   10.10.10.1   0.880 ms  0.492 ms  0.748 ms
 2   10.10.11.3   1.494 ms  1.708 ms  1.110 ms
 3   10.10.10.18   5.302 ms  2.103 ms  1.671 ms

PC1>    

PC1> trace 10.10.254.1 -P 6
trace to 10.10.254.1, 8 hops max (TCP), press Ctrl+C to stop
 1   10.10.10.1   3.082 ms  2.157 ms  27.972 ms
 2   10.10.11.4   1.342 ms  1.221 ms  0.932 ms
 3   10.10.254.1   8.937 ms  3.047 ms  3.442 ms

PC1> 

vyos@R1:~$ traceroute 10.10.10.10
traceroute to 10.10.10.10 (10.10.10.10), 30 hops max, 60 byte packets
 1  10.10.11.2 (10.10.11.2)  2.157 ms  2.100 ms  0.413 ms
 2  10.10.10.10 (10.10.10.10)  1.916 ms  1.433 ms  1.378 ms
vyos@R1:~$
```
