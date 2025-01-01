/*
 * Copyright 2024-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nycu.sdnfv.vrouter;

import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IP;
import org.onlab.packet.IPacket;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.EthType.EtherType;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.Host;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.meter.Band;
import org.onosproject.net.meter.DefaultBand;
import org.onosproject.net.meter.DefaultMeterRequest;
import org.onosproject.net.meter.Meter;
import org.onosproject.net.meter.Meter.Unit;
import org.onosproject.net.meter.MeterId;
import org.onosproject.net.meter.MeterRequest;
import org.onosproject.net.meter.MeterService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.routeservice.ResolvedRoute;
import org.onosproject.routeservice.Route;
import org.onosproject.routeservice.RouteInfo;
import org.onosproject.routeservice.RouteService;
import org.onosproject.routeservice.RouteTableId;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static org.onlab.util.Tools.get;
import static org.onlab.util.Tools.log;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;


/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true, service = {AppComponent.class})

public class AppComponent{

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final vRouterConfigLinster cfgListener = new vRouterConfigLinster();
    private final ConfigFactory<ApplicationId, vRouterConfig> factory = new ConfigFactory<ApplicationId,vRouterConfig>(
        APP_SUBJECT_FACTORY, vRouterConfig.class, "router") {
        @Override
        public vRouterConfig createConfig(){
            return new vRouterConfig();
        }
    };

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected RouteService routeService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MeterService meterService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    ApplicationId appId;
    ConnectPoint frrCP;
    MacAddress frrMac;
    Ip4Address frrIp;
    MacAddress virtualMac;
    Ip4Address virtaulIp4Addr;
    Ip6Address virtualIp6Addr;
    ArrayList<Ip4Address> v4Peers = new ArrayList<Ip4Address>();
    ArrayList<Ip6Address> v6Peers = new ArrayList<Ip6Address>();
    ArrayList<ConnectPoint> PeersCP = new ArrayList<ConnectPoint>();
    Map<IpPrefix, ConnectPoint> edgeRouterCP = new HashMap<>();
    private vRouterProcessor processor = new vRouterProcessor();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nycu.sdnfv.vrouter");
        packetService.addProcessor(processor, PacketProcessor.director(5));
        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);
        requestPacketIn();
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.removeListener(cfgListener);
        cfgService.unregisterConfigFactory(factory);
        packetService.removeProcessor(processor);
        processor = null;
        cancelPacketIn();
        log.info("Stopped");
    }
    @Modified
    public void modified(ComponentContext context){
        requestPacketIn();
    }

    private void requestPacketIn(){
        TrafficSelector selector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV4)
                        .matchEthDst(MacAddress.valueOf("00:00:00:00:00:02"))
                        .build();
        packetService.requestPackets(selector, PacketPriority.REACTIVE, appId);
        selector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV6)
                        .matchEthDst(MacAddress.valueOf("00:00:00:00:00:02"))
                        .build();
        packetService.requestPackets(selector, PacketPriority.REACTIVE, appId);
    }

    private void cancelPacketIn(){
        TrafficSelector selector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV4)
                        .matchEthDst(MacAddress.valueOf("00:00:00:00:00:02"))
                        .build();
        packetService.cancelPackets(selector, PacketPriority.REACTIVE, appId);
        selector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV6)
                        .matchEthDst(MacAddress.valueOf("00:00:00:00:00:02"))
                        .build();
        packetService.cancelPackets(selector, PacketPriority.REACTIVE, appId);
    }
    
    private class vRouterProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context){
            
            if(context.isHandled()) {
                // log.info("HANDLED");
                return;
            }
        
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            
            if(ethPkt == null) {
                log.info("ETH NULL");
                return;
            }
            // Do not process ARP and NDP packet
            if(ethPkt.getEtherType() == Ethernet.TYPE_ARP){
                log.info("APR BYE");
                return;
            }
            if(context.inPacket().parsed().getEtherType() == Ethernet.TYPE_IPV6){
                IPv6 ip6pkt = (IPv6) context.inPacket().parsed().getPayload();
                
                if(ip6pkt.getNextHeader() == IPv6.PROTOCOL_ICMP6){
                    ICMP6 icmppkt =(ICMP6) ip6pkt.getPayload();
                    if (icmppkt.getIcmpType() == ICMP6.NEIGHBOR_SOLICITATION || icmppkt.getIcmpType() == ICMP6.NEIGHBOR_ADVERTISEMENT){         
                        log.info("NA AND NS BYE");
                        return;
                    }
                }
            }
            IpAddress srcIp;
            IpAddress dstIp; 
            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();
            
            ConnectPoint inPoint = pkt.receivedFrom();
            // IPv4 or IPv6
            log.info("ETH TYPE " + ethPkt.getEtherType());
            if(ethPkt.getEtherType() == Ethernet.TYPE_IPV4){
                    IPv4 ip4Pkt = (IPv4) ethPkt.getPayload();
                    srcIp = Ip4Address.valueOf(ip4Pkt.getSourceAddress());
                    dstIp = Ip4Address.valueOf(ip4Pkt.getDestinationAddress());
                    log.info("Source Address" + srcIp);
                    log.info("Destination Address: " + dstIp);
                    // Drop BGP packet (BGP is based on TCP, check TCP packet)
                    if(ip4Pkt.getProtocol() == IPv4.PROTOCOL_TCP){
                        // BGP Protocol uses port 179
                        TCP tcpPkt = (TCP) ip4Pkt.getPayload();
                        if (tcpPkt.getDestinationPort() == 179){
                            log.info("Drop BGP Packet");
                            return;
                        }
                    }
            }
            else{
                IPv6 ip6Pkt = (IPv6) ethPkt.getPayload();
                srcIp = Ip6Address.valueOf(ip6Pkt.getSourceAddress());
                dstIp = Ip6Address.valueOf(ip6Pkt.getDestinationAddress());
                log.info("Source Address" + srcIp);
                log.info("Destination Address: " + dstIp);
                if(ip6Pkt.getNextHeader() == IPv6.PROTOCOL_TCP){
                    // BGP Protocol uses port 179
                    TCP tcpPkt = (TCP) ip6Pkt.getPayload();
                    if (tcpPkt.getDestinationPort() == 179){
                        log.info("Drop BGP Packet");
                        return;
                    }
                }
            }        
           

            // We uss Proxy ARP to tell that the gateway mac is 00:00:00:00:00:02
            // So the packet pass into controller 
            // (No mater inside or outside the AS since the OVS3 is also got the mac by Proxy ARP)
            
            ResolvedRoute route = getRoute(dstIp);
            log.info("[VROUTER] DST MAC " + dstMac);
            log.info("[VROUTER] ROUTE: " + route);
            if(dstMac.equals(virtualMac)){ 
                
                if (route == null){ // if no info of the next hop -> local or no such host
                    // Do Local
                    if(ethPkt.getEtherType() == Ethernet.TYPE_IPV4){
                        IPv4 ip4Pkt = (IPv4) ethPkt.getPayload();
                        local_dst_intent(ip4Pkt, inPoint);
                    }
                    else{
                        IPv6 ip6Pkt = (IPv6) ethPkt.getPayload();
                        local_dst_intent(ip6Pkt, inPoint);
                    }                    
                }
                else{
                    // Transit to Outside
                    // Src is local (Seems like it doesn't matter)
                    // if(getRoute(srcIp) == null){ 
                        // from inside to outside  
                        if(ethPkt.getEtherType() == Ethernet.TYPE_IPV4){
                            IPv4 ip4Pkt = (IPv4) ethPkt.getPayload();
                            IpPrefix prefix = Ip4Address.valueOf(ip4Pkt.getDestinationAddress()).toIpPrefix();
                            IpPrefix nextHopPrefix = route.nextHop().toIpPrefix();
                            MacAddress nextHopMac = route.nextHopMac();
                            transit_out_intnet(prefix, nextHopPrefix, nextHopMac, inPoint, Ethernet.TYPE_IPV4);
                        }
                        else{
                            IPv6 ip6Pkt = (IPv6) ethPkt.getPayload();
                            IpPrefix prefix = Ip6Address.valueOf(ip6Pkt.getDestinationAddress()).toIpPrefix();
                            IpPrefix nextHopPrefix = route.nextHop().toIpPrefix();
                            MacAddress nextHopMac = route.nextHopMac();
                            transit_out_intnet(prefix, nextHopPrefix, nextHopMac, inPoint, Ethernet.TYPE_IPV6);
                        }
                    // }
                    // else{
                    //     // from one outside to another outside
                    //     if(ethPkt.getEtherType() == Ethernet.TYPE_IPV4){
                    //         IPv4 ip4Pkt = (IPv4) ethPkt.getPayload();
                    //         IpPrefix dstPrefix = Ip4Address.valueOf(ip4Pkt.getDestinationAddress()).toIpPrefix();
                    //         IpPrefix nextHopPrefix = route.nextHop().toIpPrefix();
                    //         MacAddress nextHopMac = route.nextHopMac();
                    //         transit_out_intnet(dstPrefix, nextHopPrefix, nextHopMac, inPoint, Ethernet.TYPE_IPV4);
                    //     }
                    //     else{
                            

                    //     }
                        
                        
                    // }
                    
                }
            }
            

            // context.block();
        }

        private ResolvedRoute getRoute(IpAddress dstIp){
            IpPrefix prefix = dstIp.toIpPrefix();
            Collection<RouteTableId> routeTableIds = routeService.getRouteTables();
            // All routing table
            for(RouteTableId Id : routeTableIds){
                // check each routing tavle's route
                Collection<RouteInfo> routes = routeService.getRoutes(Id);
                for (RouteInfo route: routes){
                    if(route.prefix().contains(prefix)){
                        // If the prefix exists
                        return route.bestRoute().get();
                    }
                }
            }
            return null;
        }
        
        private void local_dst_intent(IPv4 ip4Pkt, ConnectPoint ingress){
            // from outside to SDN domain
            // e.g. from h2 to h1
            // change src mac to gateway mac (virtual mac)
            // change dst mac to correct mac (host's mac)

            Ip4Address dstIp = Ip4Address.valueOf((ip4Pkt.getDestinationAddress()));

            Set<Host> hosts = hostService.getHostsByIp(dstIp);
            Host dstHost = hosts.iterator().next(); // get first one
            if(hosts.isEmpty()){
                log.info("No Host at " + dstIp + ".");
                return;
            }
            log.info(hosts.size() + " Hosts.");
            for(Host host: hosts){
                log.info("Dst IP Hosts: " + host + ". IP: " + host.ipAddresses() + " MAC: " + host.mac());
            }
            MacAddress dstHostMac = dstHost.mac();
            ConnectPoint dstHostCP = ConnectPoint.fromString(dstHost.location().toString());
            log.info("Host Location" + dstHost.location().toString());
            

            TrafficSelector selector = DefaultTrafficSelector.builder()
                                .matchEthType(Ethernet.TYPE_IPV4)
                                .matchIPDst(dstIp.toIpPrefix())
                                .build();
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                .setEthSrc(virtualMac)     
                                .setEthDst(dstHostMac)
                                .build();
            FilteredConnectPoint ingressCP = new FilteredConnectPoint(ingress);
            FilteredConnectPoint engressCP = new FilteredConnectPoint(dstHostCP);

            PointToPointIntent intent = PointToPointIntent.builder()
                            .appId(appId)
                            .filteredIngressPoint(ingressCP)
                            .filteredEgressPoint(engressCP)
                            .selector(selector)
                            .treatment(treatment)
                            .priority(50)
                            .build();
            log.info("From " + virtualMac + " to " + dstHostMac);
            log.info("From " + ingressCP.toString() + " to " + engressCP.toString());
            intentService.submit(intent);
            log.info("IPv4 Intent submitted.");
        }

        private void local_dst_intent(IPv6 ip6Pkt, ConnectPoint ingress){
            // change src mac to gateway mac (virtual mac)
            // change dst mac to correct mac (host's mac)
            Ip6Address dstIp = Ip6Address.valueOf((ip6Pkt.getDestinationAddress()));

            Set<Host> hosts = hostService.getHostsByIp(dstIp);
            Host dstHost = hosts.iterator().next(); // get first one
            if(hosts.isEmpty()){
                log.info("No Host at " + dstIp + ".");
                return;
            }
            log.info(hosts.size() + " Hosts.");
            for(Host host: hosts){
                log.info("Dst IP Hosts: " + host + ". IP: " + host.ipAddresses() + " MAC: " + host.mac());
            }
            MacAddress dstHostMac = dstHost.mac();
            ConnectPoint dstHostCP = ConnectPoint.fromString(dstHost.location().toString());
            log.info("Host Location" + dstHost.location().toString());
            

            TrafficSelector selector = DefaultTrafficSelector.builder()
                                .matchEthType(Ethernet.TYPE_IPV6)
                                .matchIPv6Dst(dstIp.toIpPrefix())
                                .build();
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                .setEthSrc(virtualMac)     
                                .setEthDst(dstHostMac)
                                .build();
            FilteredConnectPoint ingressCP = new FilteredConnectPoint(ingress);
            FilteredConnectPoint engressCP = new FilteredConnectPoint(dstHostCP);

            PointToPointIntent intent = PointToPointIntent.builder()
                            .appId(appId)
                            .filteredIngressPoint(ingressCP)
                            .filteredEgressPoint(engressCP)
                            .selector(selector)
                            .treatment(treatment)
                            .priority(50)
                            .build();
            
            log.info("From " + virtualMac + " to " + dstHostMac);
            log.info("From " + ingressCP.toString() + " to " + engressCP.toString());
            intentService.submit(intent);
            log.info("IPv6 Intent submitted.");
        }

        private void transit_out_intnet(IpPrefix dstIpPrefix, IpPrefix nextHopIpPrefix, MacAddress nextHopMac, ConnectPoint ingress, short type){
            //  from local to outside AS
            //  e.g h1 to h2 (its dst ip must be router ip, that is virtual ip)
            //  change its dst mac to the R1/TA/TEAM dst
            //  change its src mac to virtual gateway mac 
            //  get edge router CP by dstIp Prefix (eg h1 to h2 172.17.16.2, but R1 gateway ip is 172.17.16.1)
            //  only change L2 address **DO NOT CHANGE IP**

            //  *****maybe we need to use route service to find next hop or mac*****
            
            ConnectPoint dstRouterCP = edgeRouterCP.get(nextHopIpPrefix);
            
            TrafficSelector selector = DefaultTrafficSelector.emptySelector();
            if (type == Ethernet.TYPE_IPV4) {
               selector = DefaultTrafficSelector.builder()
                                .matchEthType(type)
                                .matchIPDst(dstIpPrefix)
                                .build(); 
            }
            else{
                selector = DefaultTrafficSelector.builder()
                                .matchEthType(type)
                                .matchIPv6Dst(dstIpPrefix)
                                .build(); 
            }
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                .setEthSrc(virtualMac)
                                .setEthDst(nextHopMac) // need to find a way to get the mac address of edge router like R1/TA
                                .build();

            FilteredConnectPoint ingressCP = new FilteredConnectPoint(ingress);
            FilteredConnectPoint egressCP = new FilteredConnectPoint(dstRouterCP);
            PointToPointIntent intent = PointToPointIntent.builder()
                                .appId(appId)
                                .filteredIngressPoint(ingressCP)
                                .filteredEgressPoint(egressCP)
                                .selector(selector)
                                .treatment(treatment)
                                .priority(50)
                                .build();
            log.info("From " + virtualMac + " to " + nextHopMac);
            log.info("From " + ingressCP.toString() + " to " + egressCP.toString());
            intentService.submit(intent);
            log.info("TO OUTSIDE Intent submitted.");
        }
    }


    public class vRouterConfigLinster implements NetworkConfigListener{
        @Override
        public void event(NetworkConfigEvent event) {
            if((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED) 
                && event.configClass().equals(vRouterConfig.class)){
                vRouterConfig config = cfgService.getConfig(appId, vRouterConfig.class);
                if(config != null){
                    frrCP = config.getVroutingConnectPoint();
                    frrMac = config.getVroutingMac();
                    frrIp = config.getVroutingIp4();
                    virtualMac = config.getGatewayMac();
                    virtaulIp4Addr = config.getGatewayIp4();
                    virtualIp6Addr = config.getGatewayIp6();
                    v4Peers = config.getPeersV4();
                    v6Peers = config.getPeersV6();
                    log.info("FRR ConnectPoint: " + frrCP);
                    log.info("FRR Mac: " + frrMac);
                    log.info("Virtual Gateway Mac: " + virtualMac);
                    log.info("Virtual Gateway IPv4: " + virtaulIp4Addr);
                    log.info("Virtual Gateway IPv6: " + virtualIp6Addr);

                    for(Ip4Address ip : v4Peers){
                        log.info("IPv4 Peers: " + ip);
                    }
                    for(Ip6Address ip : v6Peers){
                        log.info("IPv6 Peers: " + ip);
                    }
                    // set intent between Frr and Peers (other AS's router)
                    for(int i = 0; i < v4Peers.size(); i+=2){
                        Ip4Address peerIp = v4Peers.get(i);
                        Ip4Address frrIp = v4Peers.get(i+1);
                        Interface itf = interfaceService.getMatchingInterface(peerIp);
                        // use interface service to get the connect point's interface
                        Interface frritf = interfaceService.getMatchingInterface(frrIp);
                        // from FRR to Peer(other router)
                        bgpIntentInstall(frritf.connectPoint(), itf.connectPoint(), peerIp);
                        // from Peer(other router) to FRR
                        bgpIntentInstall(itf.connectPoint(), frritf.connectPoint(), frrIp);
                        // add the infomation of edge router's IP and CP
                        edgeRouterCP.put(peerIp.toIpPrefix(), itf.connectPoint());
                    }
                    // for(Ip6Address peerIp: v6Peers){
                    for(int i = 0; i < v6Peers.size(); i+=2){
                        Ip6Address peerIp = v6Peers.get(i);
                        Ip6Address frrIp = v6Peers.get(i+1);
                        Interface itf = interfaceService.getMatchingInterface(peerIp);
                        Interface frritf = interfaceService.getMatchingInterface(frrIp);
                        // from FRR to Peer(other router)
                        bgpIntentInstall(frritf.connectPoint(), itf.connectPoint(), frrIp);
                        // from Peer(other router) to FRR
                        bgpIntentInstall(itf.connectPoint(), frritf.connectPoint(), peerIp);
                        edgeRouterCP.put(peerIp.toIpPrefix(), itf.connectPoint());
                    }

                    // install meter to R1 ovs1
                    // DeviceId ovs1DevId = DeviceId.deviceId("of:0000000000000002");
                    // // setting band
                    // List<Band> bands = new LinkedList<Band>();
                    // bands.add(DefaultBand.builder()
                    //     .ofType(Band.Type.DROP)
                    //     .withRate(1024)
                    //     .burstSize(2048)
                    //     .build());
                    //     //  log.info("I am in meter of s4 - 2");
                    // MeterRequest.Builder meterReq = DefaultMeterRequest.builder()
                    //             .forDevice(ovs1DevId)
                    //             .fromApp(appId)
                    //             .withUnit(Unit.KB_PER_SEC)
                    //             .burst()
                    //             .withBands(bands);
                    // Meter meter = meterService.submit(meterReq.add());
                    
                    // TrafficSelector selector = DefaultTrafficSelector.emptySelector();
                        
                    // TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    //                     .setOutput(PortNumber.portNumber(3))
                    //                     .meter(meter.id())
                    //                     .build();
                    //                     // log.info("I am in meter of s4 - 4");
                    // FlowRule flowRule = DefaultFlowRule.builder()
                    //             .forDevice(ovs1DevId)
                    //             .fromApp(appId)
                    //             .withSelector(selector)
                    //             .withTreatment(treatment)
                    //             .makePermanent()
                    //             .withPriority(40000)
                    //             .build();
                    // flowRuleService.applyFlowRules(flowRule);

                }
            }
        }
        private void bgpIntentInstall(ConnectPoint ingress, ConnectPoint egress, IpAddress dstIp){
            // Handle BGP messages
            TrafficSelector selector;
            if(dstIp.isIp4()){
                selector = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            .matchIPDst(dstIp.toIpPrefix())
                            .build();   
            }
            else{
                selector = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV6)
                            .matchIPv6Dst(dstIp.toIpPrefix())
                            .build();
            }
            TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();
            
            FilteredConnectPoint ingressPoint = new FilteredConnectPoint(ingress);
            FilteredConnectPoint egressPoint = new FilteredConnectPoint(egress);

           
            PointToPointIntent intent = PointToPointIntent.builder()
                            .appId(appId)
                            .filteredIngressPoint(ingressPoint)
                            .filteredEgressPoint(egressPoint)
                            .selector(selector)
                            .treatment(treatment)
                            .priority(50)
                            .build();
            intentService.submit(intent);
            log.info("BGP message from" + ingress + " to " + egress);
            return;
        } 
    }     
}
