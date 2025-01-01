/*
 * Copyright 2020-present Open Networking Foundation
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

 import java.util.ArrayList;
 import java.util.List;
 import java.util.function.Function;
 
 import org.onlab.packet.Ip4Address;
 import org.onlab.packet.Ip6Address;
 import org.onlab.packet.MacAddress;
 import org.onosproject.core.ApplicationId;
 import org.onosproject.net.config.Config;
 import org.onosproject.net.ConnectPoint;
 
 
 public class vRouterConfig extends Config<ApplicationId> {
     public static final String VROUTING_CP = "vrrouting";
     public static final String VROUTING_MAC = "vrrouting-mac";
     public static final String VROUTING_IP = "vrrouting-ip";
     public static final String GATEWAY_V4 = "gateway-ip4";
     public static final String GATEWAY_V6 = "gateway-ip6";
     public static final String GATEWAY_MAC = "gateway-mac";
     public static final String V4_PEERS = "v4-peers";
     public static final String V6_PEERS = "v6-peers";
 
     Function<String, String> func = (String e)-> {return e;};
 
     @Override
     public boolean isValid() {
       return hasFields(VROUTING_CP, VROUTING_MAC, GATEWAY_V4, GATEWAY_V6, GATEWAY_MAC, V4_PEERS, V6_PEERS);
     }
     
     public ConnectPoint getVroutingConnectPoint() {
         return ConnectPoint.fromString(get(VROUTING_CP, null));
     }
     
     public MacAddress getVroutingMac() {
         return MacAddress.valueOf(get(VROUTING_MAC, null));
     }
 
     public Ip4Address getVroutingIp4(){
         return Ip4Address.valueOf(get(VROUTING_IP, null));        
     }
 
     public Ip4Address getGatewayIp4() {
         return Ip4Address.valueOf(get(GATEWAY_V4, null));
     }    
 
     public Ip6Address getGatewayIp6() {
         return Ip6Address.valueOf(get(GATEWAY_V6, null));
     }
 
     public MacAddress getGatewayMac() {
         return MacAddress.valueOf(get(GATEWAY_MAC, null));
     }
 
     public ArrayList<Ip4Address> getPeersV4(){
         List<String> peers = getList(V4_PEERS, func);
         ArrayList<Ip4Address> v4Peers = new ArrayList<Ip4Address>();
         for (String ip : peers){
             v4Peers.add(Ip4Address.valueOf(ip));
         }
         return v4Peers;
     }
 
     public ArrayList<Ip6Address> getPeersV6(){
         List<String> peers = getList(V6_PEERS, func);
         ArrayList<Ip6Address> v6Peers = new ArrayList<Ip6Address>();
         for (String ip : peers){
             v6Peers.add(Ip6Address.valueOf(ip));
         }
         return v6Peers;
     }
 }