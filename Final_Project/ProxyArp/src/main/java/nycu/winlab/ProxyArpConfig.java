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

package nycu.winlab.ProxyArp;

import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;

public class ProxyArpConfig extends Config<ApplicationId> {
    public static final String V_IP4 = "virtual-ip4";
    public static final String V_IP6 = "virtual-ip6";
    public static final String V_MAC = "virtual-mac";
    

    @Override
    public boolean isValid() {
        return hasFields(V_IP4, V_IP6, V_MAC);
    }

    public Ip4Address getVip4(){
        return Ip4Address.valueOf(get(V_IP4, null));
    }

    public Ip6Address getVip6(){
        return Ip6Address.valueOf(get(V_IP6, null));
    }

    public MacAddress getVmac(){
        return MacAddress.valueOf(get(V_MAC, null));
    }
}
