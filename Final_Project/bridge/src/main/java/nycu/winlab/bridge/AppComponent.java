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
package nycu.winlab.bridge;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.DefaultFlowRule;

// import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
// import org.onosproject.net.flowobjective.DefaultForwardingObjective;


import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.ConnectPoint;

import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;

import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;



/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    //    private final java.util.logging.Logger log = LoggerFactory.getLogger(getClass());
    private final Logger log = LoggerFactory.getLogger(getClass());


    /** Some configurable property. */

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;


    private LearningBridgeProcessor processor = new LearningBridgeProcessor();
    private ApplicationId appId;
    private Map<DeviceId, Map<MacAddress, PortNumber>> bridgeTable = new HashMap<>();

    @Activate
    protected void activate() {

        // register your app
        appId = coreService.registerApplication("nycu.winlab.bridge");

        // add a packet processor to packetService
        packetService.addProcessor(processor, PacketProcessor.director(50));

        // install a flowrule for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        // set match field ipv4
        selector.matchEthType(Ethernet.TYPE_IPV4);
        // select IPV4 packet
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        // set match field ipv6
        selector.matchEthType(Ethernet.TYPE_IPV6);
        // select IPV4 packet
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {

        // remove flowrule installed by your app
        flowRuleService.removeFlowRulesById(appId);

        // remove your packet processor
        packetService.removeProcessor(processor);
        processor = null;

        // remove flowrule you installed for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("[bridge]Stopped");
    }

    // Declare priority timeout etc.
    private int flowPriority = 30;
    private int flowTimeout = 30;


    private class LearningBridgeProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }
            if(context.inPacket().parsed().getEtherType() == Ethernet.TYPE_ARP){
                return;
            }

            if(context.inPacket().parsed().getEtherType() == Ethernet.TYPE_IPV6){
                IPv6 ip6pkt = (IPv6) context.inPacket().parsed().getPayload();

                if (! Ip6Prefix.valueOf("fd63::/64").contains(Ip6Address.valueOf(ip6pkt.getSourceAddress())) ||
                    ! Ip6Prefix.valueOf("fd63::/64").contains(Ip6Address.valueOf(ip6pkt.getDestinationAddress()))
                ){
                    if(! Ip6Prefix.valueOf("fd70::/64").contains(Ip6Address.valueOf(ip6pkt.getSourceAddress())) ||
                        ! Ip6Prefix.valueOf("fd70::/64").contains(Ip6Address.valueOf(ip6pkt.getDestinationAddress()))
                    ){
                        if(
                            ! Ip6Prefix.valueOf("2a0b:4e07:c4:18::0/64").contains(Ip6Address.valueOf(ip6pkt.getSourceAddress())) ||
                            ! Ip6Prefix.valueOf("2a0b:4e07:c4:18::0/64").contains(Ip6Address.valueOf(ip6pkt.getDestinationAddress()))
                        ){
                            return;
                        }
                    }
                }

                if(ip6pkt.getNextHeader() == IPv6.PROTOCOL_ICMP6){
                    ICMP6 icmppkt =(ICMP6) ip6pkt.getPayload();
                    if (icmppkt.getIcmpType() == ICMP6.NEIGHBOR_SOLICITATION || icmppkt.getIcmpType() == ICMP6.NEIGHBOR_ADVERTISEMENT){
                        log.info("[bridge]NA and NS, return");           
                        return;
                    }
                }
            }
            
            if(context.inPacket().parsed().getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ip4pkt = (IPv4) context.inPacket().parsed().getPayload();
                ConnectPoint receivedFrom = context.inPacket().receivedFrom();
                log.info("[bridge] Packet received from: {}", receivedFrom);
                if(
                    ! Ip4Prefix.valueOf("172.16.18.0/24").contains(IpAddress.valueOf(ip4pkt.getSourceAddress())) ||
                    ! Ip4Prefix.valueOf("172.16.18.0/24").contains(IpAddress.valueOf(ip4pkt.getDestinationAddress()))
                ){
                    if(
                        ! Ip4Prefix.valueOf("192.168.63.0/24").contains(IpAddress.valueOf(ip4pkt.getSourceAddress())) ||
                        ! Ip4Prefix.valueOf("192.168.63.0/24").contains(IpAddress.valueOf(ip4pkt.getDestinationAddress()))
                    ){
                        if(
                            ! Ip4Prefix.valueOf("192.168.70.0/24").contains(IpAddress.valueOf(ip4pkt.getSourceAddress())) ||
                            ! Ip4Prefix.valueOf("192.168.70.0/24").contains(IpAddress.valueOf(ip4pkt.getDestinationAddress()))
                        )
                        {
                            return;
                        }
                    }
                }
            }
    
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            // if(ethPkt.getDestinationMAC() == MacAddress.valueOf("00:00:00:00:00:02"))
            // {   
            //     log.info("TO gateway");
            //     return;
            // }
            
            DeviceId recDevId = pkt.receivedFrom().deviceId();
            PortNumber recPort = pkt.receivedFrom().port();
            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();

            // rec packet-in from new device, create new table for it
            if (bridgeTable.get(recDevId) == null) {
                bridgeTable.put(recDevId, new HashMap<>());
            }

            if (bridgeTable.get(recDevId).get(srcMac) == null) {

                // the mapping of pkt's src mac and receivedfrom port wasn't store in the table of the rec device
                bridgeTable.get(recDevId).put(srcMac, recPort);
                log.info("[bridge] Add an entry to the port table of `" + recDevId +
                         "`. MAC address: `" + srcMac + "` => Port: `" + recPort + "`.");
            }

            if (bridgeTable.get(recDevId).get(dstMac) == null) {
                // the mapping of dst mac and forwarding port wasn't store in the table of the rec device
                flood(context);
                log.info("[bridge] MAC address `" + dstMac + "` is missed on `" + recDevId + "`. Flood the packet.");

            } else if (bridgeTable.get(recDevId).get(dstMac) != null) {
                // there is a entry store the mapping of dst mac and forwarding port
                packetOut(context, bridgeTable.get(recDevId).get(dstMac));
                installRule(recDevId, bridgeTable.get(recDevId).get(dstMac), srcMac, dstMac);
                log.info("[bridge] MAC address `" + dstMac + "` is matched on `" + recDevId + "`. Install a flow rule.");
            }
            // context.block();
        }
    }

    private void flood(PacketContext context) {
        packetOut(context, PortNumber.FLOOD);
    }

    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private void installRule(DeviceId devId, PortNumber portNumber, MacAddress srcMac, MacAddress dstMac) {
        // Declare selector and treatment
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
        TrafficTreatment treatment;

        selectorBuilder.matchEthSrc(srcMac).matchEthDst(dstMac);
        treatment = DefaultTrafficTreatment.builder().setOutput(portNumber).build();

        // ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
        //         .withSelector(selectorBuilder.build())
        //         .withTreatment(treatment)
        //         .withPriority(flowPriority)
        //         .withFlag(ForwardingObjective.Flag.VERSATILE)
        //         .fromApp(appId)
        //         .makeTemporary(flowTimeout)
        //         .add();
        // flowObjectiveService.forward(devId, forwardingObjective);


        //// for demo
        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(devId)
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(flowPriority)
                .fromApp(appId)
                .makeTemporary(flowTimeout)
                .build();

        flowRuleService.applyFlowRules(rule);
    }
// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

}