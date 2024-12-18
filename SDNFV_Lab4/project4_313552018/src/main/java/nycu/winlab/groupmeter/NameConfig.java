package nycu.winlab.groupmeter;

import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;

public class NameConfig extends Config<ApplicationId> {

    // Define constants for each field in hostconfig.json
    public static final String HOST_1 = "host-1";
    public static final String HOST_2 = "host-2";
    public static final String MAC_1 = "mac-1";
    public static final String MAC_2 = "mac-2";
    public static final String IP_1 = "ip-1";
    public static final String IP_2 = "ip-2";

    // Override the isValid() method to validate fields in the JSON file
    @Override
    public boolean isValid() {
        return hasOnlyFields(HOST_1, HOST_2, MAC_1, MAC_2, IP_1, IP_2);
    }

    // Getter methods for each field in the configuration
    public String host1() {
        return get(HOST_1, null);
    }

    public String host2() {
        return get(HOST_2, null);
    }

    public String mac1() {
        return get(MAC_1, null);
    }

    public String mac2() {
        return get(MAC_2, null);
    }

    public String ip1() {
        return get(IP_1, null);
    }

    public String ip2() {
        return get(IP_2, null);
    }
}

