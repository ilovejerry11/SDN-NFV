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
package nycu.winlab.vrouter;

import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IP;
import org.onlab.packet.IPacket;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.Ip6Prefix;
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
import org.onosproject.net.HostId;
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
import org.onosproject.net.intent.Key;
import org.onosproject.net.intent.MultiPointToSinglePointIntent;
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
import java.util.HashSet;
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
        appId = coreService.registerApplication("nycu.winlab.vrouter");
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
                        .build();
        packetService.requestPackets(selector, PacketPriority.REACTIVE, appId);
        selector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV6)
                        .build();
        packetService.requestPackets(selector, PacketPriority.REACTIVE, appId);
    }

    private void cancelPacketIn(){
        TrafficSelector selector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV4)
                        .build();
        packetService.cancelPackets(selector, PacketPriority.REACTIVE, appId);
        selector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV6)
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
                    // if(ip4Pkt.getProtocol() == IPv4.PROTOCOL_TCP){
                    //     // BGP Protocol uses port 179
                    //     TCP tcpPkt = (TCP) ip4Pkt.getPayload();
                    //     if (tcpPkt.getDestinationPort() == 179){
                    //         log.info("Drop BGP Packet");
                    //         return;
                    //     }
                    // }
            }
            else{
                IPv6 ip6Pkt = (IPv6) ethPkt.getPayload();
                srcIp = Ip6Address.valueOf(ip6Pkt.getSourceAddress());
                dstIp = Ip6Address.valueOf(ip6Pkt.getDestinationAddress());
                log.info("Source Address" + srcIp);
                log.info("Destination Address: " + dstIp);
                // if(ip6Pkt.getNextHeader() == IPv6.PROTOCOL_TCP){
                //     // BGP Protocol uses port 179
                //     TCP tcpPkt = (TCP) ip6Pkt.getPayload();
                //     if (tcpPkt.getDestinationPort() == 179){
                //         log.info("Drop BGP Packet");
                //         return; 
                //     }
                // }
            }        
           

            // We uss Proxy ARP to tell that the gateway mac is 00:00:00:00:00:02
            // So the packet pass into controller 
            // (No mater inside or outside the AS since the OVS3 is also got the mac by Proxy ARP)
            
            ResolvedRoute route = getRoute(dstIp);
            log.info("[VROUTER] DST MAC " + dstMac);
            log.info("[VROUTER] DST IP " + dstIp);
            log.info("[VROUTER] SRC IP " + srcIp);
            log.info("[VROUTER] IP Prefix" + dstIp.toIpPrefix());
            log.info("[VROUTER] ROUTE: " + route);
            if(dstMac.equals(virtualMac)){ 
                
                log.info("[VROUTER] Detected sdn to external packet!");
                create_internal_to_external_intent(srcMac, dstIp);
                
            }else if (dstMac.equals(frrMac)){
                log.info("[VROUTER] Detected external packet");

                if (Ip6Prefix.valueOf(virtualIp6Addr, 64).contains(dstIp)){
                    log.info("[VROUTER] to internal");

                    create_external_to_internal_intent(dstIp, inPoint);

                }

                create_transit_intent(dstIp, inPoint);
            }
            
        }

        private void create_external_to_internal_intent(IpAddress dstIp, ConnectPoint inPoint) {

            if (intentService.getIntent(
                Key.of("INTER_BACK_" + dstIp + "_" + inPoint, appId)
            ) != null){
                return;
            }

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();

            if (dstIp.isIp4()){
                selector
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(dstIp.toIpPrefix());
            } else {
                selector
                    .matchEthType(Ethernet.TYPE_IPV6)
                    .matchIPv6Dst(dstIp.toIpPrefix());
            }

            Host destination = hostService.getHostsByIp(dstIp).iterator().next();

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(virtualMac)
                .setEthDst(destination.mac());

            PointToPointIntent intent = PointToPointIntent.builder()
                .appId(appId)
                .key(Key.of("INTER_BACK_" + dstIp + "_" + inPoint, appId))
                .filteredIngressPoint(new FilteredConnectPoint(inPoint))
                .filteredEgressPoint(new FilteredConnectPoint(destination.location()))
                .selector(selector.build())
                .treatment(treatment.build())
                .priority(20)
                .build();

            intentService.submit(intent);
        }

        private void create_internal_to_external_intent(MacAddress srcMac, IpAddress dstIp) {

            ResolvedRoute route = getRoute(dstIp);

            if (route == null){
                log.warn("[VROUTER] No route found for " + dstIp);
                return;
            }

            if (intentService.getIntent(Key.of("INTER_OUT_" + srcMac + "_" + route.prefix(), appId)) != null){
                return;
            }

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();

            if (dstIp.isIp4()){
                selector
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(route.prefix());
            } else {
                selector
                    .matchEthType(Ethernet.TYPE_IPV6)
                    .matchIPv6Dst(route.prefix());
            }

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(frrMac)
                .setEthDst(route.nextHopMac());
            
            PointToPointIntent intent = PointToPointIntent.builder()
                .appId(appId)
                .key(Key.of("INTER_OUT_" + srcMac + "_" + route.prefix(), appId))
                .filteredEgressPoint(new FilteredConnectPoint(interfaceService.getMatchingInterface(route.nextHop()).connectPoint()))
                .filteredIngressPoint(new FilteredConnectPoint(hostService.getHostsByMac(srcMac).iterator().next().location()))
                .selector(selector.build())
                .treatment(treatment.build())
                .priority(20)
                .build();

            intentService.submit(intent);

        }

        private void create_transit_intent(IpAddress dstIp, ConnectPoint inPoint) {
            
            ResolvedRoute route = getRoute(dstIp);

            if (route == null){
                log.warn("[VROUTER] No route found for " + dstIp);
                return;
            }

            if (intentService.getIntent(Key.of("TRANSIT_" + route.prefix(), appId)) != null){
                return;
            }

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder().matchEthDst(frrMac);

            if (dstIp.isIp4()){
                selector
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(route.prefix());
            } else {
                selector
                    .matchEthType(Ethernet.TYPE_IPV6)
                    .matchIPv6Dst(route.prefix());
            }


            Set<FilteredConnectPoint> ingressPoints = new HashSet<>();
            ConnectPoint egressPoint = interfaceService.getMatchingInterface(route.nextHop()).connectPoint();

            for (Interface intface : interfaceService.getInterfaces()) {
                if (intface.connectPoint().equals(egressPoint)){
                    continue;
                }
                ingressPoints.add(new FilteredConnectPoint(intface.connectPoint()));
            }

            MultiPointToSinglePointIntent intent = MultiPointToSinglePointIntent.builder()
                .appId(appId)
                .key(Key.of("TRANSIT_" + route.prefix(), appId))
                .filteredEgressPoint(new FilteredConnectPoint(interfaceService.getMatchingInterface(route.nextHop()).connectPoint()))
                .filteredIngressPoints(ingressPoints)
                .build();

            intentService.submit(intent);

        }

        private ResolvedRoute getRoute(IpAddress dstIp){
            IpPrefix prefix = dstIp.toIpPrefix();
            Collection<RouteTableId> routeTableIds = routeService.getRouteTables();
            // All routing table
            for(RouteTableId Id : routeTableIds){
                // check each routing tavle's route
                Collection<RouteInfo> routes = routeService.getRoutes(Id);
                for (RouteInfo route: routes){
                    log.info("[VROUTER] Checking routes " + route.prefix() + " container " + prefix);
                    if(route.prefix().contains(prefix)){
                        // If the prefix exists
                        log.info("[VROUTER] Found Route for " + route.prefix());
                        return route.bestRoute().get();
                    }
                }
            }
            return null;
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
                    log.info("[BGP INTENT] Listing BGP intents");

                    for(Ip4Address ip : v4Peers){
                        log.info("IPv4 Peers: " + ip);
                    }
                    for(Ip6Address ip : v6Peers){
                        log.info("IPv6 Peers: " + ip);
                    }
                    log.info("[BGP INTENT] Adding IPv4 " + v4Peers.size() + " Peers");
                    // set intent between Frr and Peers (other AS's router)
                    for(int i = 0; i < v4Peers.size(); i+=2){
                        Ip4Address peerIp = v4Peers.get(i);
                        Ip4Address frrIp = v4Peers.get(i+1);
                        Interface itf = interfaceService.getMatchingInterface(peerIp);
                        Interface frritf = interfaceService.getMatchingInterface(frrIp);

                        log.info("[BGP INTENT] connecting v4 BGP from " + peerIp + " to " + frrIp );
                        log.info("[BGP INTENT] connect V4 BGP from " + frritf.connectPoint() + " to " + itf.connectPoint());
                    
                        bgpIntentInstall(frritf.connectPoint(), itf.connectPoint(), peerIp);
                        bgpIntentInstall(itf.connectPoint(), frritf.connectPoint(), frrIp);
                        // bpgIntentInstallARP(itf.connectPoint(), frritf.connectPoint());
                        edgeRouterCP.put(peerIp.toIpPrefix(), itf.connectPoint());
                    }
                    log.info("[BGP INTENT] Adding IPv6 " + v6Peers.size() + " Peers");
                    for(int i = 0; i < v6Peers.size(); i+=2){
                        Ip6Address peerIp = v6Peers.get(i);
                        Ip6Address frrIp = v6Peers.get(i+1);
                        Interface itf = interfaceService.getMatchingInterface(peerIp);
                        Interface frritf = interfaceService.getMatchingInterface(frrIp);

                        log.info("[BGP INTENT] connecting v6 BGP from " + peerIp + " to " + frrIp );
                        log.info("[BGP INTENT] connect V6 BGP from " + frritf.connectPoint() + " to " + itf.connectPoint());

                        bgpIntentInstall(frritf.connectPoint(), itf.connectPoint(), peerIp);
                        bgpIntentInstall(itf.connectPoint(), frritf.connectPoint(), frrIp);
                        // bpgIntentInstallNDP(itf.connectPoint(), frritf.connectPoint()); 
                        edgeRouterCP.put(peerIp.toIpPrefix(), itf.connectPoint());
                    }

                }
            }
        }

        private void bpgIntentInstallARP(ConnectPoint a, ConnectPoint b){
            TrafficSelector selector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_ARP)
                        .build();
            TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();
            FilteredConnectPoint ingressPoint = new FilteredConnectPoint(a);
            FilteredConnectPoint egressPoint = new FilteredConnectPoint(b);
            PointToPointIntent intent = PointToPointIntent.builder()
                        .appId(appId)
                        .key(Key.of("ARP_" + a + "_" + b, appId))
                        .filteredIngressPoint(ingressPoint)
                        .filteredEgressPoint(egressPoint)
                        .selector(selector)
                        .treatment(treatment)
                        .priority(20)
                        .build();
            intentService.submit(intent);
            return;
        }

        private void bpgIntentInstallNDP(ConnectPoint a, ConnectPoint b){
            TrafficSelector selector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV6)
                        .matchIPProtocol(IPv6.PROTOCOL_ICMP6)
                        .build();
            TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();
            FilteredConnectPoint ingressPoint = new FilteredConnectPoint(a);
            FilteredConnectPoint egressPoint = new FilteredConnectPoint(b);
            PointToPointIntent intent = PointToPointIntent.builder()
                        .appId(appId)
                        .key(Key.of("NDP_" + a + "_" + b, appId))
                        .filteredIngressPoint(ingressPoint)
                        .filteredEgressPoint(egressPoint)
                        .selector(selector)
                        .treatment(treatment)
                        .priority(20)
                        .build();
            intentService.submit(intent);
            return;
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
                            .key(Key.of("BGP_" + ingress + "_" + egress + "_" + dstIp, appId))
                            .filteredIngressPoint(ingressPoint)
                            .filteredEgressPoint(egressPoint)
                            .selector(selector)
                            .treatment(treatment)
                            .priority(20)
                            .build();
            intentService.submit(intent);
            log.info("BGP message from" + ingress + " to " + egress);
            return;
        } 
    }     
}
