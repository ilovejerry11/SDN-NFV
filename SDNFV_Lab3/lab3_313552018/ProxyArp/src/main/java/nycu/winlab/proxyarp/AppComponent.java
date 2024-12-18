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
package nycu.winlab.proxyarp;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onlab.packet.Ethernet;
import org.onlab.packet.ARP;
import org.onlab.packet.MacAddress;
import org.onlab.packet.Ip4Address;

import java.util.HashMap;
import java.util.Map;
import java.nio.ByteBuffer;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;

import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;

import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;
import org.onosproject.net.ConnectPoint;

import org.onosproject.net.edge.EdgePortService;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());
    /** Some configurable property. */

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;


    private ProxyArpProcessor processor = new ProxyArpProcessor();
    private ApplicationId appId;
    private Map<MacAddress, ConnectPoint> cpTable = new HashMap<>();
    private Map<Ip4Address, MacAddress> arpTable = new HashMap<>();

    @Activate
    protected void activate() {

        // register your app
        appId = coreService.registerApplication("nycu.winlab.ProxyArp");

        // add a packet processor to packetService
        packetService.addProcessor(processor, PacketProcessor.director(2));
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        // remove your packet processor
        packetService.removeProcessor(processor);
        processor = null;

        log.info("Stopped");
    }

    private class ProxyArpProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            ARP arpDatagram = (ARP) ethPkt.getPayload();
            Ip4Address srcIp = Ip4Address.valueOf(arpDatagram.getSenderProtocolAddress());
            Ip4Address dstIp = Ip4Address.valueOf(arpDatagram.getTargetProtocolAddress());
            MacAddress srcMac = ethPkt.getSourceMAC();

            ConnectPoint inPort = pkt.receivedFrom();
            DeviceId recDevId = pkt.receivedFrom().deviceId();
            PortNumber recPort = pkt.receivedFrom().port();

// VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV      TODO      VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV

            // Record the mapping of src IP-MAC wasn't store in the table.
            arpTable.putIfAbsent(srcIp, srcMac);
            // Record the src MAC-received_from_port wasn't store in the table.
            cpTable.putIfAbsent(srcMac, inPort);
            MacAddress dstMac = arpTable.get(dstIp); // return null if key does not exist

            if (arpDatagram.getOpCode() == ARP.OP_REQUEST) {
                if (arpTable.get(dstIp) == null) {
                // the mapping of dst IP-MAC wasn't store in the table
                flood(ethPkt, inPort);
                log.info("TABLE MISS. Send request to edge ports");

                } else if (arpTable.get(dstIp) != null) {
                    // there is a entry store the dst IP-MAC mapping
                    // Packet-out ARP reply to the host sending ARP request
                    Ethernet ethArpReply = ARP.buildArpReply(dstIp, dstMac, ethPkt);
                    packetOut(ethArpReply, inPort); // (srcMac)
                    log.info("TABLE HIT. Requested MAC = {}", dstMac.toString());
                }
            } else if (arpDatagram.getOpCode() == ARP.OP_REPLY) {
                ConnectPoint outPort = cpTable.get(dstMac);
                packetOut(ethPkt, outPort); // (dstMac)
                log.info("RECV REPLY. Requested MAC = {}", srcMac.toString());
            }
        }
    }

    private void flood(Ethernet etherFrame, ConnectPoint inPort) {
        // Controller flood packet-out to the switches except the switch send packet-in
        // and switch flood ARP_request to their edge ports. (don't send to another switch)
        for (ConnectPoint cp : edgePortService.getEdgePoints()) {
            if (cp.equals(inPort)) {
                continue; // Don't send back to the incoming port
            }
            packetOut(etherFrame, cp); // Send the packet out on the edge port
        }
    }

    private void packetOut(Ethernet etherFrame, ConnectPoint outPort) {
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
        treatment.setOutput(outPort.port());

        OutboundPacket outboundPacket = new DefaultOutboundPacket(
            outPort.deviceId(), treatment.build(), ByteBuffer.wrap(etherFrame.serialize())
        );

        packetService.emit(outboundPacket);
    }
}
// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
