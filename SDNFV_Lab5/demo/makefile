main:
	docker compose up -d
	sudo ovs-vsctl add-br ovsbr1
	sudo ovs-vsctl set bridge ovsbr1 protocols=OpenFlow14
	sudo ovs-vsctl set-controller ovsbr1 tcp:127.0.0.1:6653
	sudo ovs-vsctl add-br ovsbr2
	sudo ovs-vsctl set bridge ovsbr2 protocols=OpenFlow14
	sudo ovs-vsctl set-controller ovsbr2 tcp:127.0.0.1:6653
	sudo ovs-docker add-port ovsbr1 eth1 R1 --ipaddress=172.18.0.2/16
	sudo ovs-docker add-port ovsbr2 eth1 R2 --ipaddress=172.19.0.2/16
	sudo ovs-docker add-port ovsbr1 eth1 h1 --ipaddress=172.18.0.3/16
	sudo ovs-docker add-port ovsbr2 eth1 h2 --ipaddress=172.19.0.3/16
	docker exec h1 ip route add default via 172.18.0.2
	docker exec h2 ip route add default via 172.19.0.2
clean:
	docker compose down
	sudo ovs-vsctl del-br ovsbr1
	sudo ovs-vsctl del-br ovsbr2
