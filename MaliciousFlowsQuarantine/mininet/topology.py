import os
import sys
import time

from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.node import RemoteController, Host, OVSSwitch


def topology():
    net = Mininet(ipBase="10.0.0.0/8", link=TCLink)
    
    # info("*** Adding controller ***\n")
    controller = net.addController(name="controller", 
                                   controller=RemoteController,
                                   protocol="tcp",
                                   ip="127.0.0.1",
                                   port=6653)
    
    # info("*** Adding switches ***\n")
    s1 = net.addSwitch("s1", cls=OVSSwitch, dpid="00:00:00:00:00:00:00:06", protocols="OpenFlow13")
    s2 = net.addSwitch("s2", cls=OVSSwitch, dpid="00:00:00:00:00:00:00:07", protocols="OpenFlow13")
    s3 = net.addSwitch("s3", cls=OVSSwitch, dpid="00:00:00:00:00:00:00:08", protocols="OpenFlow13")
    s4 = net.addSwitch("s4", cls=OVSSwitch, dpid="00:00:00:00:00:00:00:09", protocols="OpenFlow13")
    
    # info("*** Adding hosts ***\n")
    client1 = net.addHost("client1", cls=Host, ip="10.0.0.1", mac="00:00:00:00:00:01", defaultRoute="client1-eth0")
    client2 = net.addHost("client2", cls=Host, ip="10.0.0.2", mac="00:00:00:00:00:02", defaultRoute="client2-eth0")
    server1 = net.addHost("server1", cls=Host, ip="10.0.0.3", mac="00:00:00:00:00:03", defaultRoute="server1-eth0")
    server2 = net.addHost("server2", cls=Host, ip="10.0.0.4", mac="00:00:00:00:00:04", defaultRoute="server2-eth0")
    server3 = net.addHost("server3", cls=Host, ip="10.0.0.5", mac="00:00:00:00:00:05", defaultRoute="server3-eth0")
    
    # info("*** Adding links ***\n")
    net.addLink(client1, s1)
    net.addLink(client2, s1)
    net.addLink(s1, s4)
    net.addLink(s1, s2)
    net.addLink(s1, s3)
    net.addLink(s2, server1)
    net.addLink(s2, server2)
    net.addLink(s3, server3)
    
    # info("*** Starting network ***\n")
    net.build()
    net.start()
    
    # start UDP echo-server on the servers
    for s in server1, server2, server3:
        s.cmd('python mininet/EchoServer.py &')
    
    CLI(net)
    
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
    