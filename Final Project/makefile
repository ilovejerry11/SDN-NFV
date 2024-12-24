br-ta:
    sudo ovs-vsctl add-br br-ta -- set bridge br-ta protocols=OpenFlow14 -- set-controller br-ta tcp:192.168.100.1:6653
    sudo ovs-vsctl add-port br-ta TO_TA_VXLAN -- set interface TO_TA_VXLAN type=vxlan options:remote_ip=192.168.60.18
    sudo ip link add veth0 type veth peer name veth1
    sudo ovs-vsctl add-port br-ta veth0
    sudo ip link set veth0 up
    sudo ip link set veth1 up
    sudo ip address add 192.168.100.1/24 dev veth1
onos:
    sudo docker run --rm --name onos -d -p 8181:8181 -p 6653:6653 -p 8101:8101 onosproject/onos:2.7-latest
clean:
