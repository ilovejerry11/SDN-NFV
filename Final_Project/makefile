.PHONY: ovs1 ovs2 onos shell pign clean all

all: onos ovs1 ovs2 shell

noONOS: ovs1 ovs2

# Target to set up the bridge and VXLAN
ovs1:
	sudo ovs-vsctl add-br ovs1 -- set bridge ovs1 other_config:datapath-id=0000000000000001 -- set bridge ovs1 protocols=OpenFlow14 -- set-controller ovs1 tcp:192.168.100.1:6653

ovs2:
	sudo ovs-vsctl add-br ovs2 -- set bridge ovs2 other_config:datapath-id=0000000000000002 -- set bridge ovs2 protocols=OpenFlow14 -- set-controller ovs2 tcp:192.168.100.1:6653
	sudo ovs-vsctl add-port ovs2 TO_TA_VXLAN -- set interface TO_TA_VXLAN type=vxlan options:remote_ip=192.168.60.18
	sudo ovs-vsctl add-port ovs2 TO_TM17_VXLAN -- set interface TO_TM17_VXLAN type=vxlan options:remote_ip=192.168.61.17
	sudo ovs-vsctl add-port ovs2 TO_TM16_VXLAN -- set interface TO_TM16_VXLAN type=vxlan options:remote_ip=192.168.61.16
	sudo ip link add veth0 type veth peer name veth1
	sudo ovs-vsctl add-port ovs2 veth0
	sudo ip link set veth0 up
	sudo ip link set veth1 up
	sudo ip address add 192.168.100.1/24 dev veth1

# Target to run the ONOS container
onos:
	sudo docker run --rm --name onos -d -e ONOS_APPS=drivers,fpm,openflow,route-service,gui2 \
	-p 8181:8181 -p 6653:6653 -p 8101:8101 -p 2620:2620 onosproject/onos:2.7-latest
shell:
	sudo ./topo_utils.sh
	
install:
	cd /home/demo/Documents/repository/Final_Project/vrouter && onos-app localhost install! target/vrouter-1.0-SNAPSHOT.oar || true
	cd /home/demo/Documents/repository/Final_Project/ProxyArp && onos-app localhost install! target/ProxyArp-1.0-SNAPSHOT.oar || true
	cd /home/demo/Documents/repository/Final_Project/bridge && onos-app localhost install! target/bridge-1.0-SNAPSHOT.oar || true
	onos-netcfg localhost config.json
ping:
	sudo docker exec -it h1 ping -c3 172.16.18.69 # h1 ping FRR(R1)
	sudo docker exec -it h1 ping -c3 172.17.18.2 # h1 ping h2
	sudo docker exec -it R2 ping -c3 192.168.63.1 # R2 ping FRR(R1)
	# sudo docker exec -it R2 ping -c3 172.16.18.2 # R2 ping h1
	# sudo docker exec -it h2 ping -c3 172.16.18.2 # h2 ping h1
	sudo docker exec -it R1 ping -c3 192.168.70.253 # R1 ping ta
ping6:
	sudo docker exec -it h1 ping6 -c3 2a0b:4e07:c4:18::69 # h1 ping FRR
	sudo docker exec -it h1 ping6 -c3 2a0b:4e07:c4:118::2 # h1 ping h2
	# sudo docker exec -it h2 ping6 -c3 2a0b:4e07:c4:18::2 # h2 ping h1
	sudo docker exec -it R1 ping -c3 fd70::fe # R1 ping ta
route:
	sudo docker exec -it R2 ip route 
	sudo docker exec -it R1 ip route
route6:
	sudo docker exec -it R2 ip -6 route 
	sudo docker exec -it R1 ip -6 route
neigh:
	sudo docker exec -it R2 ip neigh
	sudo docker exec -it R1 ip neigh
# Target to clean up the setup
clean:
	sudo ovs-vsctl del-br ovs1 || true
	sudo ovs-vsctl del-br ovs2 || true 
	basename -a /sys/class/net/veth* | xargs -I {} sudo ip link del {} 2>/dev/null || true

	sudo docker stop onos || true
	sudo docker stop R1 R2 h1 h2 || true
	sudo docker rm R1 R2 h1 h2 || true
build:
	cd /home/demo/Documents/repository/Final_Project/ProxyArp && mvn clean install -DskipTests
	cd /home/demo/Documents/repository/Final_Project/bridge && mvn clean install -DskipTests
	cd /home/demo/Documents/repository/Final_Project/vrouter && mvn clean install -DskipTests