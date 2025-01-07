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
package nycu.winlab.ProxyArp;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
// libs about flow operation
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
// libs about packet type
import org.onlab.packet.Ethernet;
import org.onlab.packet.ARP;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.ndp.NeighborAdvertisement;
import org.onlab.packet.ndp.NeighborSolicitation;
import org.onlab.packet.MacAddress;
import org.onlab.packet.ICMP6;
import org.onlab.packet.Ip6Address;

// libs about packet operation
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.edge.EdgePortService;

import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.ConnectPoint;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import java.util.Map;
/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent{

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final proxyArpConfigListener cfgListener = new proxyArpConfigListener();

    private final ConfigFactory<ApplicationId, ProxyArpConfig> factory = new ConfigFactory<ApplicationId,ProxyArpConfig>(
        APP_SUBJECT_FACTORY, ProxyArpConfig.class, "virtual-arps") {
            @Override
            public ProxyArpConfig createConfig(){
                return new ProxyArpConfig();
            }
    };

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgeService;

    private ApplicationId appId;
    private Ip6Address virtual_adv_ip6; // [?] what is the use?
    private ArrayList<ConnectPoint> edgePorts;
    private ProxyArpProcessor processor = new ProxyArpProcessor();
    private Map<Ip4Address, MacAddress> arpTable = new HashMap<>();
    // To store where the reply should go
    private Map<MacAddress, ConnectPoint> pointTable = new HashMap<>(); 
    private Map<Ip6Address, MacAddress> ndpCache = new HashMap<>();
    private Map<MacAddress, ConnectPoint> ndpPointTable = new HashMap<>();
   
    
    
    @Activate
    protected void activate() {

        appId = coreService.registerApplication("nycu.winlab.ProxyArp");

        packetService.addProcessor(processor, PacketProcessor.director(2));

        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);

        // install a flowrule for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        // NS
        // set match field
        selector.matchEthType(Ethernet.TYPE_IPV6).matchIPProtocol(IPv6.PROTOCOL_ICMP6).matchIcmpv6Type(ICMP6.NEIGHBOR_SOLICITATION);
        // select IPV4 packet
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        // NA
        selector.matchEthType(Ethernet.TYPE_IPV6).matchIPProtocol(IPv6.PROTOCOL_ICMP6).matchIcmpv6Type(ICMP6.NEIGHBOR_ADVERTISEMENT);
        // select IPV4 packet
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        
        // Add controller <IP, Mac> to ARP table
        // arpTable.put(Ip4Address.valueOf("192.168.100.1"), MacAddress.valueOf( "92:84:fa:c8:7f:f3"));
        Ip4Address virtual_ip4 = Ip4Address.valueOf("172.16.18.1");
        Ip6Address virtual_ip6 = Ip6Address.valueOf("ff02::1:ff00:1");
        MacAddress virtual_mac = MacAddress.valueOf("00:00:00:00:00:02");
        arpTable.put(virtual_ip4, virtual_mac);
        ndpCache.put(virtual_ip6, virtual_mac);
        log.info("[ARP Proxy] Started.");
        log.info("[ARP Proxy] table: " + arpTable);
    }

    @Deactivate
    protected void deactivate() {

        packetService.removeProcessor(processor);
        processor = null;

        cfgService.removeListener(cfgListener);
        cfgService.unregisterConfigFactory(factory);

        // remove flowrule you installed for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV6).matchIPProtocol(IPv6.PROTOCOL_ICMP6).matchIcmpv6Type(ICMP6.NEIGHBOR_SOLICITATION);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        
        selector.matchEthType(Ethernet.TYPE_IPV6).matchIPProtocol(IPv6.PROTOCOL_ICMP6).matchIcmpv6Type(ICMP6.NEIGHBOR_ADVERTISEMENT);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        log.info("Stopped.");
    }

    private class ProxyArpProcessor implements PacketProcessor{
        
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()){
                return;
            }
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
        
        
            if (ethPkt == null){
                return;
            } 
            if(ethPkt.getEtherType() != Ethernet.TYPE_ARP && ethPkt.getEtherType() != Ethernet.TYPE_IPV6){
                return;
            }
            // get connect point info
            ConnectPoint inPortPoint = pkt.receivedFrom();

            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP){
                // convert to ARP packet 
                ARP arpPacket = (ARP) ethPkt.getPayload();

                // convert bytes to Ip4Address
                Ip4Address dstIpv4 = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());
                Ip4Address srcIpv4 = Ip4Address.valueOf(arpPacket.getSenderProtocolAddress());

                // get MAC Addresses
                MacAddress dstMac = ethPkt.getDestinationMAC();
                MacAddress srcMac = ethPkt.getSourceMAC();          
                
                arpTable.putIfAbsent(srcIpv4, srcMac);
                pointTable.putIfAbsent(srcMac, inPortPoint);

                // if this arp packet is a request
                if(arpPacket.getOpCode() == ARP.OP_REQUEST){  
                    // Proxy ARP looks up ARP Table         
                    // If mapping exists           
                    if(arpTable.get(dstIpv4) != null){
                        Ethernet arpReply = ARP.buildArpReply(dstIpv4, arpTable.get(dstIpv4), ethPkt);
                        packetOut(arpReply, inPortPoint);
                        
                        log.info("ARP TABLE HIT. Requested MAC = " + arpTable.get(dstIpv4));
                    }
                    // If table miss
                    else if(arpTable.get(dstIpv4) == null){
                        flood(ethPkt, inPortPoint);
                        log.info("ARP TABLE MISS. Send request to edge ports");
                    }
                }
                else{
                    ConnectPoint outputPoint = pointTable.get(dstMac);
                    packetOut(ethPkt, outputPoint);
                    log.info("ARP RECV REPLY. Requested MAC = " + srcMac);
                }
            }
            else{
                IPv6 ipv6Packet = (IPv6) ethPkt.getPayload();
                // NDP
                // If this is a NDP request
                Ip6Address srcIp6Address = Ip6Address.valueOf(ipv6Packet.getSourceAddress());
                Ip6Address dstIp6Address = Ip6Address.valueOf(ipv6Packet.getDestinationAddress());
                MacAddress srcMac = ethPkt.getSourceMAC();
                MacAddress dstMac = ethPkt.getDestinationMAC();
                ndpCache.put(srcIp6Address, srcMac);
                
                ndpPointTable.put(srcMac, inPortPoint);
                

                if(ipv6Packet.getNextHeader() == IPv6.PROTOCOL_ICMP6){
                    //if type is 135
                    ICMP6 icmp6Packet = (ICMP6) ipv6Packet.getPayload();
                    if(icmp6Packet.getIcmpType() == ICMP6.NEIGHBOR_SOLICITATION){

                        NeighborSolicitation ndp = (NeighborSolicitation) icmp6Packet.getPayload();
                        log.info("[NDP]NS Packet Detected from " + dstIp6Address);
                        log.info("[NDP]NS Packet Detected cache: " + ndpCache.get(dstIp6Address));
                        log.info("[NDP]NS Packet from In Point " + inPortPoint);

                        log.info("[ND_DEBUG] NS Cache List:");
                        for (var entry: ndpCache.entrySet() ){
                            log.info("[ND_DEBUG] IP: " + entry.getKey() + "\t\tMAC: " + entry.getValue());
                        }
                        // table miss
                        if(ndpCache.get(dstIp6Address) == null){                            
                            //send request to all edge ports
                            flood(ethPkt, inPortPoint);
                            log.info("[NDP]NDP TABLE MISS. Flood NDP NS");
                        }
                        else{
                            // reply
                            Ethernet ndpReply = NeighborAdvertisement.buildNdpAdv(Ip6Address.valueOf(ndp.getTargetAddress()), ndpCache.get(dstIp6Address), ethPkt);
                            IPv6 ndpPayload = (IPv6) ndpReply.getPayload();
                            ndpPayload.setHopLimit((byte)255);
                            ndpReply.setPayload(ndpPayload);
                            log.info("NDP HopLimit + "+ (int)ndpPayload.getHopLimit());
                            
                            packetOut(ndpReply, inPortPoint); 
                            log.info("[NDP]NDP TABLE HIT. Requested MAC = " + ndpCache.get(dstIp6Address));
                        }
                            
                    }
                    else if(icmp6Packet.getIcmpType() == ICMP6.NEIGHBOR_ADVERTISEMENT){
                        ndpCache.put(srcIp6Address, srcMac);
                        ConnectPoint outputPoint = ndpPointTable.get(dstMac);
                        packetOut(ethPkt, outputPoint);
                        // flood(ethPkt, inPortPoint);
                        log.info("[NDP]RECV NDP NA. Requested MAC = " + srcMac);
                    }
                }
                // context.block();
                return;
                
            }

        }
        private void flood(Ethernet ethPacket, ConnectPoint point) {
            // packet out except for input point            
            for(ConnectPoint edgePoint: edgeService.getEdgePoints()){

                if(edgePorts.contains(edgePoint)){
                    continue;
                }

                if(!edgePoint.equals(point)){ // [?] where to flood? why skip edgePorts?
                    log.info("[NDP] FLOOD to "+ edgePoint);
                    packetOut(ethPacket, edgePoint);
                }
            }
        }
    
        private void packetOut(Ethernet ethPacket, ConnectPoint point) {
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                    .setOutput(point.port())
                                    .build();
            OutboundPacket outPkt = new DefaultOutboundPacket(
                point.deviceId(), treatment, ByteBuffer.wrap(ethPacket.serialize()));
            // send to the specify port
        
            log.info("Packet OUT "+ ethPacket.getDestinationMAC());
            packetService.emit(outPkt);
        }
    } 
    
    public class proxyArpConfigListener implements NetworkConfigListener{
        @Override
        public void event(NetworkConfigEvent event){
            ProxyArpConfig config = cfgService.getConfig(appId,ProxyArpConfig.class);
            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
                    && event.configClass().equals(ProxyArpConfig.class)) {
                if(config != null){
                    edgePorts = config.getEdgePorts();
                    Ip4Address virtual_ip4 = config.getVip4();
                    Ip6Address virtual_ip6 = config.getVip6();
                    MacAddress virtual_mac = config.getVmac();
                    // MacAddress frr_mac = config.getFrrmac();
                    virtual_adv_ip6 = config.getAdvVip6();
                    

                    log.info("Virtual IPv4\t" + virtual_ip4);
                    log.info("Virtual IPv6\t" + virtual_ip6);
                    log.info("Virtual MAC\t" + virtual_mac);

                    arpTable.put(virtual_ip4, virtual_mac);
                    ndpCache.put(virtual_ip6, virtual_mac);
                }
            }
        }
    }   
}
