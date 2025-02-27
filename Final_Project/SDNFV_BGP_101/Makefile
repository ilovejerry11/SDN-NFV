.PHONY: ALL

export IMAGES=host

define gen_host
	$(eval $@_CNAME = $(1))
	$(eval $@_CIMG  = $(2))

	$(eval $@_PID = `docker run --rm --cap-add NET_ADMIN -t --name ${$@_CNAME} --network none -l app=sdnfv-demo -l app.name=${$@_CNAME} -d ${$@_CIMG} | xargs docker inspect -f '{{.State.Pid}}'`)
	mkdir -p /var/run/netns
	ln -sfT /proc/${$@_PID}/ns/net /var/run/netns/${$@_CNAME}
endef

define connect
	$(eval $@_C1 = $(1))
	$(eval $@_C2 = $(2))
	$(eval $@_IP1= $(3))
	$(eval $@_IP2= $(4))
	$(eval $@_L1=veth${$@_C1}${$@_C2})
	$(eval $@_L2=veth${$@_C2}${$@_C1})

	ip link add ${$@_L1} type veth peer name ${$@_L2}
	ip link set ${$@_L1} netns ${$@_C1}
	ip link set ${$@_L2} netns ${$@_C2}
	ip netns exec ${$@_C1} ip link set ${$@_L1} up
	ip netns exec ${$@_C2} ip link set ${$@_L2} up
	ip netns exec ${$@_C1} ip a a ${$@_IP1} dev ${$@_L1}
	ip netns exec ${$@_C2} ip a a ${$@_IP2} dev ${$@_L2}
endef

build:
	@for image in $$IMAGES; do \
		docker build dockerfiles -t $$image:latest -f dockerfiles/$$image.Dockerfile; \
	done

lab-01:

	@echo In this lab, you shall assign IP
	@printf "\t h1 IP: 192.168.0.1/24\n"
	@printf "\t h2 IP: 192.168.0.2/24\n"
	@echo After assigning IP, you have to make sure that h1 can ping 192.168.0.2
	
	@$(call gen_host, "h1", "host")
	@$(call gen_host, "h2", "host")

	#TODO write the code below to ensure that h1 can ping 192.168.0.2, which is h2's IP

	ip link add vethh1h2 type veth peer name vethh2h1
	ip link set vethh1h2 netns h1
	ip link set vethh2h1 netns h2
	ip netns exec h1 ip link set vethh1h2 up
	ip netns exec h2 ip link set vethh2h1 up
	ip netns exec h1 ip addr add 192.168.0.1/24 dev vethh1h2
	ip netns exec h2 ip addr add 192.168.0.2/24 dev vethh2h1

tu-01: clean-lab
	@echo In this tutorial, I will show you basic informations about routing tables

	@$(call gen_host, "h1", "host")
	@$(call gen_host, "h2", "host")
	@$(call gen_host, "h3", "host")
	@$(call connect, h1, h2, 192.168.0.2/24, 192.168.0.1/24)
	@$(call connect, h3, h2, 192.168.1.2/24, 192.168.1.1/24)

lab-02:
	@echo In this lab, you shall assign IP
	@printf "\t h1 IP: 192.168.0.2/24\n"
	@printf "\t h2 IP: 192.168.1.2/24\n"
	@printf "\t R1 IP: 192.168.0.1/24, 192.168.2.1\n"
	@printf "\t R2 IP: 192.168.1.1/24, 192.168.2.2\n"

	@$(call gen_host, "h1", "host")
	@$(call gen_host, "h2", "host")
	@$(call gen_host, "R1", "host")
	@$(call gen_host, "R2", "host")

	#TODO write the code below to ensure that h1 can ping 192.168.1.2, which is h2's IP
	@$(call connect, h1, R1, 192.168.0.2/24, 192.168.0.1/24)
	@$(call connect, h2, R2, 192.168.1.2/24, 192.168.1.1/24)
	@$(call connect, R1, R2, 192.168.2.1/24, 192.168.2.2/24)

	ip netns exec h1 ip route add default via 192.168.0.1
	ip netns exec h2 ip route add default via 192.168.1.1
	ip netns exec R1 ip route add 192.168.1.0/24 via 192.168.2.2
	ip netns exec R2 ip route add 192.168.0.0/24 via 192.168.2.1

useful:
	sudo docker exec -it R1 ip route show

test-01: clean-lab lab-01
	@docker exec -it h1 ping -c 3 -W 1 192.168.0.2 && \
		echo "LAB SUCCESSED!" || \
		echo "LAB FAILED!"

test-02: clean-lab lab-02
	@docker exec -it h1 ping -c 3 -W 1 192.168.1.2 && \
		echo "LAB SUCCESSED!" || \
		echo "LAB FAILED!"

clean-lab:
	@for container in `docker ps --filter "label=app=sdnfv-demo" --format '{{.Names}}'`; do \
		rm /var/run/netns/$$container; \
	done
	@docker ps -q --filter "label=app=sdnfv-demo" | xargs docker stop 2>/dev/null | true
	@basename -a /sys/class/net/veth* | grep -e '\([Rh][0-9]\)\{2\}' | xargs -I {} ip l del {} 2>/dev/null | true

