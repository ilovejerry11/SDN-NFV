/*
 * Copyright 2023-present Open Networking Foundation
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

import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;
import org.onosproject.net.ConnectPoint;
import org.onlab.packet.MacAddress;
import org.onlab.packet.IpAddress;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public class vRouterConfig extends Config<ApplicationId> {
    public static final String FRR_LOCATION = "vrouter";
    public static final String FRR_MAC = "vrouter-mac";
    public static final String FRR_GWIP4 = "gateway-ip4";
    public static final String FRR_GWIP6 = "gateway-ip6";
    public static final String FRRGW_MAC = "gateway-mac";
    public static final String V4PEERS = "v4-peers";
    public static final String V6PEERS = "v6-peers";
    public static final String FRR_IP = "vrouterip";

    Function<String, String> func = (String e)-> {return e;};

    @Override
    public boolean isValid() {
        return hasFields(FRR_LOCATION, FRR_MAC, FRR_GWIP4, FRR_GWIP6, FRR_MAC, V4PEERS, V6PEERS);
    }

    public ConnectPoint getVroutingConnectPoint() {
        return ConnectPoint.fromString(get(FRR_LOCATION, null));
    }

    public MacAddress getVroutingMac() {
        return MacAddress.valueOf(get(FRR_MAC, null));
    }

    public MacAddress getGatewayMac() {
        return MacAddress.valueOf(get(FRRGW_MAC, null));
    }

    public Ip4Address getGatewayIp4() {
        return Ip4Address.valueOf(get(FRR_GWIP4, null));
    }

    public Ip6Address getGatewayIp6() {
        return Ip6Address.valueOf(get(FRR_GWIP6, null));
    }

    public Ip4Address getVrroutingIp4() {
        return Ip4Address.valueOf(get(FRR_IP, null));
    }

    public ArrayList<Ip4Address> getPeersV4() {
        List<String> peers = getList(V4PEERS, func);
        ArrayList<Ip4Address> peersIp = new ArrayList<Ip4Address>();
       
        for (String peerIp : peers) {
            peersIp.add(Ip4Address.valueOf(peerIp));
        }
       
        return peersIp;
    }

    public ArrayList<Ip6Address> getPeersV6() {
        List<String> peers = getList(V6PEERS, func);
        ArrayList<Ip6Address> peersIp = new ArrayList<Ip6Address>();
       
        for (String peerIp : peers) {
            peersIp.add(Ip6Address.valueOf(peerIp));
        }
       
        return peersIp;
    }
}