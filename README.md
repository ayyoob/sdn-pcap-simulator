# sdn-pcap-simulator
This is a sdn based pcap simulator. This contains a simple virtual switch with the support of adding custom 
application logic to test sdn based application alogirithms. Please note current version does not support all OF 
capabilities. Please raise an issue if any new features are required.

By default we have provided an example of the applications that we implemented for https://arxiv.org/abs/1902.02484.
# Prerequisite
LibPcap (install tcpdump)

# Installation

```sh
$ git clone https://github.com/ayyoob/sdn-pcap-simulator.git
$ cd sdn-pcap-simulator
$ mvn clean install
```


# Execute

```sh
$ java -jar target/sdn-simulator-1.0.0-SNAPSHOT.jar target/default_config.json
```


# Configurations
simulator-config in https://github.com/ayyoob/sdn-pcap-simulator/blob/master/src/main/resources/apps
/all_app_simulator_config.json, lists out configurations for different sdn based applications.
    

    "pcapLocation": "absolute file path of the pcap"

Location of the traffic trace.

    "switchConfig": { "macAddress" : "14:cc:20:51:33:ea", "ipAddress": "192.168.1.1", "ipv6Address": "fe80:0:0:0:16cc:20ff:fe51:33ea" }

In order to capture device to Internet communication, we require the default gateway details. Therefore mac address, IP addresses of the default gateway has to be given through the config. 
If you are using a router for your setup then this details can be fetched through its management page in its web UI.


    "modules": [
            "com.ayyoob.sdn.of.simulator.apps.legacydevice.LegacyDeviceIdentifier"
        ]
This is a full qualified class name that implemenents the com.ayyoob.sdn.of.simulator.apps.ControllerApp Interface. 
This implmentation can handle packet in. An example of the implementation can be seen on com.ayyoob.sdn.of.simulator
.apps.legacydevice.LegacyDeviceIdentifier.

    "statModules": [
            "com.ayyoob.sdn.of.simulator.apps.legacydevice.LegacyDeviceStatsCollector",
            "com.ayyoob.sdn.of.simulator.apps.legacydevice.LegacyDeviceFlowOptimizer"
        ]
This is a full qualified class name that implemenents the com.ayyoob.sdn.of.simulator.apps.StatListener Interface. 
An event will be triggered each time a packet is being being inspected. The implementtattion of this interface should
 handle the timing. An example of the implementation can be seen on com.ayyoob.sdn.of.simulator.apps.legacydevice
 .LegacyDeviceStatsCollector.
 
    "moduleConfig": {
             "LegacyDeviceIdentifier": {
                 "enable": true,
                 "deviceMac" : "e0:a7:00:02:44:1b",
                 "gatewayIp" : "192.168.1.1",
                 "gatewayIpv6" : "fe80:0:0:0:16cc:20ff:fe51:33ea",
                 "dpId":"14:cc:20:51:33:ea",
                 "idleTimeoutInSeconds": 60
             }
         }"
Module config will be passed to each applications during the initialization. Class name of each application will be a
 key in the config.
 
    

