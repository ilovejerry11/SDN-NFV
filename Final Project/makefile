.PHONY: ovs2 onos clean all

all: onos ovs1 ovs2

noONOS: ovs1 ovs2

# Target to set up the bridge and VXLAN
ovs1:
	sudo ovs-vsctl add-br ovs1 -- set bridge ovs1 protocols=OpenFlow14 -- set-controller ovs1 tcp:192.168.100.1:6653
ovs2:
	sudo ovs-vsctl add-br ovs2 -- set bridge ovs2 protocols=OpenFlow14 -- set-controller ovs2 tcp:192.168.100.1:6653
	sudo ovs-vsctl add-port ovs2 TO_TA_VXLAN -- set interface TO_TA_VXLAN type=vxlan options:remote_ip=192.168.60.18
	sudo ip link add veth0 type veth peer name veth1
	sudo ovs-vsctl add-port ovs2 veth0
	sudo ip link set veth0 up
	sudo ip link set veth1 up
	sudo ip address add 192.168.100.1/24 dev veth1

# Target to run the ONOS container
onos:
	sudo docker run --rm --name onos -d -e ONOS_APPS=drivers,fpm,fwd,openflow,route-service,gui2 \
	-p 8181:8181 -p 6653:6653 -p 8101:8101 onosproject/onos:2.7-latest

# Target to clean up the setup
clean:
	sudo ovs-vsctl del-br ovs1 || true
	sudo ovs-vsctl del-br ovs2 || true 
	basename -a /sys/class/net/veth* | xargs -I {} sudo ip link del {} 2>/dev/null || true

	sudo docker stop onos || true
	sudo docker stop R1 R2 h1 h2 || true
	sudo docker rm R1 R2 h1 h2 || true
