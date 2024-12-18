package nycu.winlab.groupmeter;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.GroupId;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficTreatment;
// import org.onosproject.net.flowobjective.ForwardingObjective;
// import org.onosproject.net.flowobjective.DefaultForwardingObjective;
// import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.FlowRuleService;

import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketPriority;

import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.PointToPointIntent;

// import org.onosproject.net.group.Group;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.group.GroupBucket;
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.DefaultGroupBucket;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.DefaultGroupDescription;
// import org.onosproject.net.group.GroupDescription.Type;
import org.onosproject.net.group.GroupKey;
import org.onosproject.net.group.DefaultGroupKey;

import org.onosproject.net.meter.Band;
import org.onosproject.net.meter.DefaultBand;
import org.onosproject.net.meter.MeterRequest;
import org.onosproject.net.meter.DefaultMeterRequest;
import org.onosproject.net.meter.Meter;
import org.onosproject.net.meter.MeterId;
import org.onosproject.net.meter.MeterService;
import org.onosproject.net.meter.Meter.Unit;

import org.onlab.packet.Ethernet;
// import org.onlab.packet.IPv4;
import org.onlab.packet.ARP;
// import org.onlab.packet.TCP;
// import org.onlab.packet.UDP;
import org.onlab.packet.MacAddress;
import org.onlab.packet.Ip4Address;

import java.util.Collections;
import java.util.Map; // use on building MacTable
import java.util.HashMap;
import java.nio.ByteBuffer;

/** Sample Network Configuration Service Application. **/
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final NameConfigListener cfgListener = new NameConfigListener();

    private final ConfigFactory<ApplicationId, NameConfig> factory = new ConfigFactory<ApplicationId, NameConfig>(
        APP_SUBJECT_FACTORY, NameConfig.class, "informations") {
        @Override
        public NameConfig createConfig() {
            return new NameConfig();
        }
    };

    private ApplicationId appId;
    private MeterId meterId;
    private IntentProcesser intentProcesser = new IntentProcesser();
    private MacAddress h1Mac;
    private MacAddress h2Mac;
    private DeviceId cpIdH1;
    private PortNumber cpPortNumberH1;
    private DeviceId cpIdH2;
    private PortNumber cpPortNumberH2;

    private static final PortNumber PORT_1 = PortNumber.portNumber(1);
    private static final PortNumber PORT_2 = PortNumber.portNumber(2);
    private static final PortNumber PORT_3 = PortNumber.portNumber(3);

    private static final DeviceId DEVICE_1 = DeviceId.deviceId("of:0000000000000001");
    private static final DeviceId DEVICE_2 = DeviceId.deviceId("of:0000000000000002");
    private static final DeviceId DEVICE_3 = DeviceId.deviceId("of:0000000000000003");
    private static final DeviceId DEVICE_4 = DeviceId.deviceId("of:0000000000000004");
    private static final DeviceId DEVICE_5 = DeviceId.deviceId("of:0000000000000005");

    private static final int GROUP_ID = 1;

    private static final int FLOW_PRIORITY = 30;
    private static final int FLOW_TIMEOUT = 30;

    // private Map<MacAddress, ConnectPoint> cpTable = new HashMap<>();
    private Map<Ip4Address, MacAddress> arpTable = new HashMap<>();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MeterService meterService;

    // @Reference(cardinality = ReferenceCardinality.MANDATORY)
    // protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nycu.winlab.groupmeter");
        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);
        packetService.addProcessor(intentProcesser, PacketProcessor.director(3)); // add processor

        // install a flowrule for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.removeListener(cfgListener);
        cfgService.unregisterConfigFactory(factory);
        packetService.removeProcessor(intentProcesser);
        // // Remove groups and meter associated with this app
        removeFailoverGroup();
        removeMeter();

        // remove flowrule you installed for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        // remove flowrule installed by your app
        flowRuleService.removeFlowRulesById(appId);

        log.info("Stopped");
    }

    private class IntentProcesser implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) {
                return;
            }
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                // ArpProxy
                ARP arpDatagram = (ARP) ethPkt.getPayload();
                // Ip4Address srcIp = Ip4Address.valueOf(arpDatagram.getSenderProtocolAddress());
                Ip4Address dstIp = Ip4Address.valueOf(arpDatagram.getTargetProtocolAddress());
                MacAddress dstMac = arpTable.get(dstIp);
                Ethernet ethArpReply = ARP.buildArpReply(dstIp, dstMac, ethPkt);
                ConnectPoint inPort = pkt.receivedFrom();
                packetOut(ethArpReply, inPort);
                log.info("ARP reply.");
                return;
            }

            if (ethPkt.getEtherType() != Ethernet.TYPE_IPV4) {
                log.info("Not TYPE_IPV4!");
                return;
            }
            // DeviceId recDevId = pkt.receivedFrom().deviceId();
            // PortNumber recPort = pkt.receivedFrom().port();
            // MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();

            // ConnectPoint inPort = pkt.receivedFrom();
            // DeviceId recDevId = pkt.receivedFrom().deviceId();
            // PortNumber recPort = pkt.receivedFrom().port();
            // basic info of packet\
            ConnectPoint cp = pkt.receivedFrom();
            DeviceId deviceId = cp.deviceId();
            PortNumber inPort = cp.port();
            log.info("ReceivedFrom deviceId: {}, inPort: {}, dstMac: {}", deviceId, inPort, dstMac);

            PointToPointIntent intent;
            TrafficSelector selector;
            FilteredConnectPoint ingressPoint = new FilteredConnectPoint(cp);

            if (dstMac.equals(h2Mac)) {
                ConnectPoint cp2 = new ConnectPoint(cpIdH2, cpPortNumberH2); // s5, port1
                FilteredConnectPoint egressPoint2 = new FilteredConnectPoint(cp2);
                selector = DefaultTrafficSelector.builder()
                    .matchEthDst(h2Mac)
                    .build();

                intent = PointToPointIntent.builder()
                    .appId(appId)
                    .filteredIngressPoint(ingressPoint)
                    .filteredEgressPoint(egressPoint2)
                    .selector(selector)
                    .priority(FLOW_PRIORITY)
                    .build();
                intentService.submit(intent);
                log.info("Intent {}, port {} => {}, port {} is submitted.", deviceId, inPort, cpIdH2, cpPortNumberH2);
                // packetOut(ethPkt, cp);
            } else if (dstMac.equals(h1Mac)) {
                ConnectPoint cp1 = new ConnectPoint(cpIdH1, cpPortNumberH1);
                FilteredConnectPoint egressPoint1 = new FilteredConnectPoint(cp1);
                selector = DefaultTrafficSelector.builder()
                .matchEthDst(h1Mac)
                .build();

                intent = PointToPointIntent.builder()
                    .appId(appId)
                    .filteredIngressPoint(ingressPoint)
                    .filteredEgressPoint(egressPoint1)
                    .selector(selector)
                    .priority(FLOW_PRIORITY)
                    .build();
                intentService.submit(intent);
                log.info("Intent {}, port {} => {}, port {} is submitted.", deviceId, inPort, cpIdH1, cpPortNumberH1);
                // packetOut(ethPkt, cp);
            } else {
                log.info("dstMac {} dose not equals to MacAddress of h1 or h2.", dstMac);
            }
        }
    }

    private class NameConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
                && event.configClass().equals(NameConfig.class)) {
                    NameConfig config = cfgService.getConfig(appId, NameConfig.class);
                    h1Mac = MacAddress.valueOf(config.mac1());
                    h2Mac = MacAddress.valueOf(config.mac2());
                    Ip4Address h1Ip4 = Ip4Address.valueOf(config.ip1());
                    Ip4Address h2Ip4 = Ip4Address.valueOf(config.ip2());
                    if (config != null) {
                        arpTable.putIfAbsent(h1Ip4, h1Mac);
                        arpTable.putIfAbsent(h2Ip4, h2Mac);

                        String[] splitted;
                        splitted = config.host1().split("/");
                        cpIdH1 = DeviceId.deviceId(splitted[0]);
                        cpPortNumberH1 = PortNumber.portNumber(splitted[1]);
                        splitted = config.host2().split("/");
                        cpIdH2 = DeviceId.deviceId(splitted[0]);
                        cpPortNumberH2 = PortNumber.portNumber(splitted[1]);

                        log.info("ConnectPoint_h1: {}, ConnectPoint_h2: {}", config.host1(), config.host2());
                        log.info("MacAddress_h1: {}, MacAddress _h2: {}", config.mac1(), config.mac2());
                        log.info("IpAddress_h1: {}, IpAddress_h2: {}", config.ip1(), config.ip2());
                        // log.info("connected to {}, port {}", cpIdH2, cpPortNumberH2);
                    }
                installFailoverGroup();
                installMeter(h1Mac);
            }
        }

        private void installFailoverGroup() {
            GroupId groupId = GroupId.valueOf(GROUP_ID);
            GroupKey groupKey = new DefaultGroupKey("failoverGroup".getBytes());

            GroupBucket bucket1 = DefaultGroupBucket.createFailoverGroupBucket(
                DefaultTrafficTreatment.builder().setOutput(PORT_2).build(), PORT_2, null
            );

            GroupBucket bucket2 = DefaultGroupBucket.createFailoverGroupBucket(
                DefaultTrafficTreatment.builder().setOutput(PORT_3).build(), PORT_3, null
            );

            GroupBuckets buckets = new GroupBuckets(Collections.unmodifiableList(
                java.util.Arrays.asList(bucket1, bucket2))
            );

            GroupDescription groupDescription = new DefaultGroupDescription(
                DEVICE_1,
                GroupDescription.Type.FAILOVER,
                buckets,
                groupKey,
                GROUP_ID,
                appId
            );

            // Code for actually installing the group would go here, e.g.:
            groupService.addGroup(groupDescription);

            TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(PORT_1)
                .matchEthType(Ethernet.TYPE_IPV4) // prerequisite
                // .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .build();

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .group(groupId)
                .build();

            FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(DEVICE_1)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(30)
                .fromApp(appId)
                .makePermanent()
                .build(); // Builds a flow rule object.

            flowRuleService.applyFlowRules(flowRule);
        }

        private void installMeter(MacAddress h1Mac) {
            MeterRequest meterRequest = DefaultMeterRequest.builder()
                .forDevice(DEVICE_4)
                .fromApp(appId)
                .withUnit(Unit.KB_PER_SEC)
                .withBands(Collections.singletonList(DefaultBand.builder()
                    .ofType(Band.Type.DROP)
                    .withRate(512)
                    .burstSize(1024)
                    .build()))
                .add();

            Meter meter = meterService.submit(meterRequest);
            meterId = meter.id();

            // log.info("Meter installed with ID: {}", meterId);

            TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthSrc(h1Mac)
                .build();

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .meter(meterId)
                .setOutput(PORT_2)
                .build();

            FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(DEVICE_4)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(30)
                .fromApp(appId)
                .makePermanent()
                .build(); // Builds a flow rule object.

            flowRuleService.applyFlowRules(flowRule);
        }
    }

    private void packetOut(Ethernet ethPkt, ConnectPoint cp) {
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
        treatment.setOutput(cp.port());

        OutboundPacket outboundPacket = new DefaultOutboundPacket(
            cp.deviceId(), treatment.build(), ByteBuffer.wrap(ethPkt.serialize())
        );

        packetService.emit(outboundPacket);
    }

    private void removeFailoverGroup() {
        GroupKey groupKey = new DefaultGroupKey("failoverGroup".getBytes());
        groupService.removeGroup(DEVICE_1, groupKey, appId);
    }

    private void removeMeter() {
        Meter meter = meterService.getMeter​(DEVICE_4, meterId);
        MeterRequest meterRequest = DefaultMeterRequest.builder()
            .forDevice(meter.deviceId())
            .fromApp(appId) // Replace appId with the correct app instance variable
            .withUnit(meter.unit())
            .withBands(meter.bands())
            .remove();

        // Withdraw the meter
        meterService.withdraw(meterRequest, meter.id());
    }
}

