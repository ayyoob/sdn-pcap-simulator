package com.ayyoob.sdn.of.simulator.apps.attackdetector;

import com.ayyoob.sdn.of.simulator.Constants;
import com.ayyoob.sdn.of.simulator.OFController;
import com.ayyoob.sdn.of.simulator.OFFlow;
import com.ayyoob.sdn.of.simulator.SimPacket;
import com.ayyoob.sdn.of.simulator.apps.ControllerApp;
import com.ayyoob.sdn.of.simulator.apps.StatListener;
import com.ayyoob.sdn.of.simulator.apps.deployer.mudflowdto.DeviceMUDFlowMap;
import com.ayyoob.sdn.of.simulator.apps.legacydevice.processor.mud.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.simple.JSONObject;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class MudAttackDetector implements ControllerApp, StatListener{

    private static boolean enabled = true;
    private String switchMac;
    private String deviceMac;
    private final int FIXED_LOCAL_COMMUNICATION = 5;
    private final int DEFAULT_LOCAL_COMMUNICATION = 4;
    private final int FIXED_INTERNET_COMMUNICATION = 10;
    private final int FIXED_LOCAL_CONTROLLER_COMMUNICATION = 15;
    private final int DEFAULT_INTERNET_COMMUNICATION = 9;
    private final String MUD_URN = "urn:ietf:params:mud";
    private boolean setup = false;
    private String gatewayIp;
    private Map<String, List<OFFlow>> deviceFlowMapHolder = new HashMap<>();
    private static Map<String, Map<OFFlow, EntropyData>> entropy10000Data = new HashMap<>();
    private static Map<String, Map<OFFlow, EntropyData>> entropy5000Data = new HashMap<>();
    private static Map<String, Map<OFFlow, EntropyData>> entropy1000Data = new HashMap<>();
    private Map<String, String> ipMacMapping = new HashMap<>();
    private String arpfilename;
    private String entropy10000filename;
    private String entropy5000filename;
    private String entropy1000filename;
    private String flowcounterfilename;
    private String flowSizefilename;
    private PrintWriter arpwriter = null;
    private long flowSummerizationTimeInMillis = 60000;
    private String FROM_LOCAL_FEATURE_NAME = "FromLocal%sPort%s";
    private String TO_LOCAL_FEATURE_NAME = "ToLocal%sPort%s";
    private String FROM_INTERNET_FEATURE_NAME = "FromInternet%sPort%s";
    private String TO_INTERNET_FEATURE_NAME = "ToInternet%sPort%s";
    private String IP_TAG = "IP";
    private long last10000LogTime = 0;
    private long last5000LogTime = 0;
    private long last1000LogTime = 0;
    private long lastFlowLogTime = 0;
    private long lastPacketTime = 0;
    private List<String> entropy10000String = new ArrayList<>();
    private List<String> entropy5000String = new ArrayList<>();
    private List<String> entropy1000String = new ArrayList<>();
    private List<String> flowCounterdata = new ArrayList<>();
    private List<String> flowSizedata = new ArrayList<>();
    private Set<OFFlow> lastFlow = new HashSet<OFFlow>();
    private boolean clearFlows = false;
    private boolean skipFlowsChromecast = true;
    private static boolean monitorFlows = true;
    private static Map<String, EntropyHold> entropyHoldMap = new HashMap();

    private static List<SimPacket> chromecastPacketLog = new ArrayList<>();


    @Override
    public void init(JSONObject jsonObject) {
        if (!setup) {
            entropy10000Data = new HashMap<>();
            entropy5000Data = new HashMap<>();
            entropy1000Data = new HashMap<>();
            enabled = (Boolean) jsonObject.get("enabled");
            if (!enabled) {
                return;
            }
            switchMac = (String) jsonObject.get("dpId");
            gatewayIp = (String) jsonObject.get("gatewayIp");
            deviceMac = (String) jsonObject.get("device");
            monitorFlows = (boolean) jsonObject.get("attackDetect");
            String mudFilePath = (String) jsonObject.get("mud");
            String ipListFile = (String) jsonObject.get("ipListFile");
            try {
                byte[] encoded = Files.readAllBytes(Paths.get(mudFilePath));
                String mudPayload = new String(encoded, Charset.defaultCharset());

                addMudConfigs(mudPayload, deviceMac, switchMac);


            } catch (IOException e) {
                e.printStackTrace();
            }

            String currentPath = Paths.get(".").toAbsolutePath().normalize().toString();

            File workingDirectory = new File(currentPath + File.separator + "result");
            if (!workingDirectory.exists()) {
                workingDirectory.mkdir();
            }

            Map<OFFlow, EntropyData> flow10000EntropyData = new HashMap<>();
            for (OFFlow ofFlow : deviceFlowMapHolder.get(deviceMac)) {
                flow10000EntropyData.put(ofFlow, new EntropyData());
            }
            entropy10000Data.put(deviceMac, flow10000EntropyData);


            Map<OFFlow, EntropyData> flow5000EntropyData = new HashMap<>();
            for (OFFlow ofFlow : deviceFlowMapHolder.get(deviceMac)) {
                flow5000EntropyData.put(ofFlow, new EntropyData());
            }
            entropy5000Data.put(deviceMac, flow5000EntropyData);


            Map<OFFlow, EntropyData> flow1000EntropyData = new HashMap<>();
            for (OFFlow ofFlow : deviceFlowMapHolder.get(deviceMac)) {
                flow1000EntropyData.put(ofFlow, new EntropyData());
            }
            entropy1000Data.put(deviceMac, flow1000EntropyData);


            //
            ipMacMapping.put(switchMac, gatewayIp);
            BufferedReader br = null;
            String line;
            try {

                br = new BufferedReader(new FileReader(ipListFile));
                while ((line = br.readLine()) != null) {
                    // use comma as separator
                    String[] ipMac = line.split(",");
                    ipMacMapping.put(ipMac[0].toLowerCase(), ipMac[1]);
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (br != null) {
                    try {
                        br.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }

            arpfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") +
                    "_arpspoof" + ".csv";
            try {
                arpwriter = new PrintWriter(new BufferedWriter(
                        new FileWriter(arpfilename)), true);
            } catch (IOException e) {
                e.printStackTrace();
            }
            arpwriter.println("timestamp, srcMac, dstMac, requestSrcMac, requestSrcIp, requestTargetMac, " +
                    "requestTargetIPMac");



            entropy10000filename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":",
                    "") +
                    "_entropy" + 10000 + ".csv";
            entropy5000filename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":",
                    "") +
                    "_entropy" + 5000 + ".csv";
            entropy1000filename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":",
                    "") +
                    "_entropy" + 1000 + ".csv";

            StringBuilder header = new StringBuilder();
            for (OFFlow ofFlow : deviceFlowMapHolder.get(deviceMac)) {
                header.append(ofFlow.getName())
                        .append(",");
            }
            String flowId = header.toString();
            flowId= flowId.substring(0, flowId.length()-1);
            String flowfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":",
                    "") +
                    "_flowid.csv";
            try{
                FileWriter fw=new FileWriter(flowfilename);
                fw.write(flowId);
                fw.close();
            }catch(Exception e){System.out.println(e);}


            header = new StringBuilder("timestamp");
            for (OFFlow ofFlow : deviceFlowMapHolder.get(deviceMac)) {
                header.append(",")
                        .append(ofFlow.getName() + "_"+ "srcIP")
                        .append(",")
                        .append(ofFlow.getName() + "_"+ "dstIP")
                        .append(",")
                        .append(ofFlow.getName() + "_"+ "srcPort")
                        .append(",")
                        .append(ofFlow.getName() + "_"+ "dstPort")
                        .append(",")
                        .append(ofFlow.getName() + "_"+ "icmpCode")
                        .append(",")
                        .append(ofFlow.getName() + "_"+ "icmpType");
            }
            entropy10000String.add(header.toString());
            entropy5000String.add(header.toString());
            entropy1000String.add(header.toString());

            flowcounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") +
                    "_flowcounter_" + flowSummerizationTimeInMillis + "sec.csv";
            flowSizedata.add("Timestamp,size");

            flowSizefilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") +
                    "_flowsize.csv";

            flowCounterdata.add("timestamp,flowname,packetcount,bytecount,flowid");
            setup = true;
        }

        System.out.println("Total Flow Count: " + OFController.getInstance().getSwitch(switchMac).getAllFlows().size());

    }

    @Override
    public void process(String dpId, long timestamp) {
        if (!enabled) {
            return;
        }
        if (!this.switchMac.equals(dpId)) {
            return;
        }
        process10000Entropy(dpId, timestamp);
        process5000Entropy(dpId, timestamp);
        process1000Entropy(dpId, timestamp);

        processFlowLog(dpId, timestamp);

    }


    public void process10000Entropy(String dpId, long timestamp) {

        long nextLogTime = 0;
        long summerizationTimeInMillis = 10000;
        if (last10000LogTime == 0) {
            last10000LogTime = timestamp;
            return;
        }
        nextLogTime = last10000LogTime + 10000;
        long currentTime = timestamp;
        while (currentTime >= nextLogTime) {
            entropy10000String.add(nextLogTime + getEntropyFlowString(entropy10000Data));

            if (monitorFlows) {
                for (String entropyHoldKey : entropyHoldMap.keySet()) {
                    EntropyHold entropyHold = entropyHoldMap.get(entropyHoldKey);
//                    EntropyHoldData entropyHoldData = entropyHold.getPrevEntropyHoldData();

                    if (entropyHoldKey.startsWith("From")) {
                        entropyHold.caculateCost();
                        boolean ipAttack = contains(entropyHoldKey, "srcIP");
                        boolean portAttack = contains(entropyHoldKey, "srcPort");
                        if (portAttack) {
                            int maxCount = 0;
                            String maxIp = "*";
                            for (String ip : entropyHold.getSrcMap().keySet()) {
                                if (maxCount < entropyHold.getSrcMap().get(ip).size()) {
                                    maxCount = entropyHold.getSrcMap().get(ip).size();
                                    maxIp = ip;
                                }
                            }


                            if (!maxIp.equals("*")) {
                                System.out.println("blocking src ip:" + maxIp + " maxCount: " + maxCount);
                                OFFlow ofFlow = entropyHold.getOfFlow().copy();
                                ofFlow.setSrcIp(maxIp);
                                ofFlow.setPriority(2000);
                                ofFlow.setIdleTimeOut(40* 60 * 1000);
                                ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                                System.out.println(timestamp + " OFFlow pushed " + ofFlow.getFlowString());
                                OFController.getInstance().addFlow(dpId, ofFlow);
                            }
                        }
                        if (ipAttack) {
                            //identify the most repeated ports in all ips and block that ip
                            Map<String, Integer> portCount = new HashMap<>();
                            for (String ip : entropyHold.getSrcMap().keySet()) {
                                for (String port : entropyHold.getSrcMap().get(ip)) {
                                    if (portCount.containsKey(port)) {
                                        portCount.put(port, portCount.get(port) + 1);
                                    } else {
                                        portCount.put(port, 1);
                                    }
                                }
                            }
                            int max = 0;
                            String portx = "";
                            for (String port : portCount.keySet()) {
                                if (portCount.get(port) > max) {
                                    portx = port;
                                    max = portCount.get(port);
                                }
                            }

//                            if (portx.equals("8899") || portx.equals("8900")) {
                                System.out.println("blocking src port:" + portx);
                                OFFlow ofFlow = entropyHold.getOfFlow().copy();
                                ofFlow.setSrcPort(portx);
                                ofFlow.setPriority(2000);
                                ofFlow.setIdleTimeOut(40 * 60 * 1000);
                                ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                                System.out.println(timestamp + " OFFlow pushed " + ofFlow.getFlowString());
                                OFController.getInstance().addFlow(dpId, ofFlow);
//                            }
                        }
//                            if (totalFlowGrowth > 25) {
//                                System.out.printf("%s, : %f,%f,%f \n", entropyHoldKey
//                                        , (current.SrcIpSize - prev.SrcIpSize) * 100.0 / prev.SrcIpPortSize
//                                        , (current.SrcPortSize - prev.SrcPortSize) * 100.0 / prev.SrcIpPortSize
//                                        , (current.SrcIpPortSize - prev.SrcIpPortSize) * 100.0 / prev.SrcIpPortSize
//                                );
//                            }

                    } else {
                        boolean ipAttack = contains(entropyHoldKey, "dstIP");
                        boolean portAttack = contains(entropyHoldKey, "dstPort");
                      entropyHold.caculateCost();
                        if (portAttack) {
                            //identify most random ports in a ip and block that ip
                            int maxCount = 0;
                            String maxIp = "*";
                            for (String ip : entropyHold.getDstMap().keySet()) {
                                if (maxCount < entropyHold.getDstMap().get(ip).size()) {
                                    maxCount = entropyHold.getDstMap().get(ip).size();
                                    maxIp = ip;
                                }
                            }
                            if (!maxIp.equals("*")) {
                                System.out.println("blocking dst ip:" + maxIp);
                                OFFlow ofFlow = entropyHold.getOfFlow().copy();
                                ofFlow.setDstIp(maxIp);
                                ofFlow.setPriority(1000);
                                ofFlow.setIdleTimeOut(40 * 60 * 1000);
                                ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                                System.out.println(timestamp + " OFFlow pushed " + ofFlow.getFlowString());
                                OFController.getInstance().addFlow(dpId, ofFlow);
                            }


                        }
                        if (ipAttack) {
                            //identify the most repeated ports in all ips and block that ip
                            Map<String, Integer> portCount = new HashMap<>();
                            for (String ip : entropyHold.getDstMap().keySet()) {
                                for (String port : entropyHold.getDstMap().get(ip)) {
                                    if (portCount.containsKey(port)) {
                                        portCount.put(port, portCount.get(port) + 1);
                                    } else {
                                        portCount.put(port, 1);
                                    }
                                }
                            }
                            int max = 0;
                            String portx = "";
                            for (String port : portCount.keySet()) {
                                if (portCount.get(port) > max) {
                                    portx = port;
                                    max = portCount.get(port);
                                }
                            }



//                            if (portx.equals("8899") || portx.equals("8900")) {
                                System.out.println("blocking dst port:" + portx);
                                OFFlow ofFlow = entropyHold.getOfFlow().copy();
                                ofFlow.setDstPort(portx);
                                ofFlow.setPriority(1000);
                                ofFlow.setIdleTimeOut(40 * 60 * 1000);
                                ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                                System.out.println(timestamp + " OFFlow pushed " + ofFlow.getFlowString());
                                OFController.getInstance().addFlow(dpId, ofFlow);
//                            }
                        }
                    }


                }
            }

            resetEntropyFlow(entropy10000Data);
            nextLogTime = nextLogTime + summerizationTimeInMillis;


        }
        last10000LogTime = nextLogTime - summerizationTimeInMillis;

        if (entropy10000String.size() > 10000) {
            try {
                writeEntropyRaw(entropy10000String, entropy10000filename);
                entropy10000String.clear();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }
    private static int dstCounter = 3;
    private boolean contains(String flow, String type) {
//        String flowIds[] = {"FromLocalTCPPort49153_srcPort", "ToLocalTCPPort49153_dstPort"};
//        String flowIds[] = {"FromLocalTCPPort49153_srcIP", "ToLocalTCPPort49153_dstIP"};
        String flowIds[] = {"FromLocalTCPPort49153_srcPort", "ToLocalTCPPort49153_dstPort", "FromLocalTCPPort49153_srcIP", "ToLocalTCPPort49153_dstIP"};
        for (String fl : flowIds) {
            if (fl.startsWith(flow) && fl.contains(type)) {
                if (fl.equals("ToLocalTCPPort49153_dstIP")) {

                    if (dstCounter != 0) {
                        dstCounter--;
                        continue;
                    }
                }
                return true;
            }
        }
        return false;
    }

    public void process5000Entropy(String dpId, long timestamp) {

        long nextLogTime = 0;
        long summerizationTimeInMillis = 5000;
        if (last5000LogTime == 0) {
            last5000LogTime = timestamp;
            return;
        }
        nextLogTime = last5000LogTime + 5000;
        long currentTime = timestamp;
        while (currentTime >= nextLogTime) {
            entropy5000String.add(nextLogTime + getEntropyFlowString(entropy5000Data));
            resetEntropyFlow(entropy5000Data);
            nextLogTime = nextLogTime + summerizationTimeInMillis;

        }
        last5000LogTime = nextLogTime - summerizationTimeInMillis;

        if (entropy5000String.size() > 10000) {
            try {
                writeEntropyRaw(entropy5000String, entropy5000filename);
                entropy5000String.clear();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    public void process1000Entropy(String dpId, long timestamp) {

        long nextLogTime = 0;
        long summerizationTimeInMillis = 1000;
        if (last1000LogTime == 0) {
            last1000LogTime = timestamp;
            return;
        }
        nextLogTime = last1000LogTime + 1000;
        long currentTime = timestamp;
        while (currentTime >= nextLogTime) {
            entropy1000String.add(nextLogTime + getEntropyFlowString(entropy1000Data));
            resetEntropyFlow(entropy1000Data);
            nextLogTime = nextLogTime + summerizationTimeInMillis;

        }
        last1000LogTime = nextLogTime - summerizationTimeInMillis;

        if (entropy1000String.size() > 10000) {
            try {
                writeEntropyRaw(entropy1000String, entropy1000filename);
                entropy1000String.clear();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }


    public void processFlowLog(String dpId, long timestamp) {
        long nextLogTime = 0;
        if (lastFlowLogTime == 0) {
            lastFlowLogTime = timestamp;
            return;
        }
        nextLogTime = lastFlowLogTime + flowSummerizationTimeInMillis;
        long currentTime = timestamp;


        if (currentTime >= nextLogTime) {
            lastFlowLogTime = currentTime;
            buildVolumeData(lastFlowLogTime);

            int flowCount = OFController.getInstance().getSwitch(switchMac).getAllFlows().size();
            flowSizedata.add(timestamp + "," + flowCount);

            if (clearFlows) {
                if (OFController.getInstance().getSwitch(dpId).getAllFlows().size() > 300) {
                    OFController.getInstance().getSwitch(dpId).removeFlows(FIXED_INTERNET_COMMUNICATION + 1);
                    OFController.getInstance().getSwitch(dpId).removeFlows(FIXED_LOCAL_COMMUNICATION + 1);
                    OFController.getInstance().getSwitch(dpId).removeFlows(FIXED_LOCAL_CONTROLLER_COMMUNICATION + 1);
                }
            }
        }

        if (flowCounterdata.size() > 10000) {
            try {
                writeFlowRaw(flowCounterdata);
                writeFlowCounterRaw(flowSizedata);
                flowCounterdata.clear();
                flowSizedata.clear();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        lastPacketTime = currentTime;
    }

    private String getEntropyFlowString(Map<String, Map<OFFlow,EntropyData >> entropyData) {
        String data = "";
        for (OFFlow flow : deviceFlowMapHolder.get(deviceMac)) {
            data = data  + entropyData.get(deviceMac).get(flow).calculateShannonEntropy();
        }
        return  data;
    }

    private void resetEntropyFlow(Map<String, Map<OFFlow,EntropyData >> entropyData) {
        for (OFFlow flow : deviceFlowMapHolder.get(deviceMac)) {
            entropyData.get(deviceMac).get(flow).clearData();
        }
    }

    @Override
    public void process(String dpId, SimPacket packet) {

        if (packet.getIpProto() != null && packet.getIpProto().equals(Constants.UDP_PROTO) && packet.getSrcPort()
                .equals(Constants.DHCP_PORT)) {

            // get DHCP response

        } else if (packet.getEthType() != null && packet.getEthType().equals(Constants.ETH_TYPE_ARP)) {
            //arp spoof detector
            try {
                EthernetPacket ethernetPacket = EthernetPacket.newPacket(packet.getData(), 0, packet.getData().length);
                ArpPacket arpPacket = ArpPacket.newPacket(ethernetPacket.getPayload().getRawData(), 0,
                        ethernetPacket.getPayload().getRawData().length);
                ArpPacket.ArpHeader arpHeader = arpPacket.getHeader();
                if (arpHeader.getOperation() == ArpOperation.REPLY) {
                    if (ipMacMapping.get(arpHeader.getSrcHardwareAddr().toString()) != null && !ipMacMapping.get
                            (arpHeader.getSrcHardwareAddr().toString()).equals(arpHeader.getSrcProtocolAddr()
                            .getHostAddress())) {
                        //spoof logger
                        arpwriter.println(packet.getTimestamp() + "," +ethernetPacket.getHeader().getSrcAddr().toString
                                () +
                                "," +
                                ethernetPacket.getHeader().getDstAddr().toString() + "," +
                                arpHeader.getSrcHardwareAddr() + "," +
                                arpHeader.getSrcProtocolAddr() + "," +
                                arpHeader.getDstHardwareAddr() + "," +
                                arpHeader.getDstProtocolAddr() );
                    } else if (ipMacMapping.get(arpHeader.getDstHardwareAddr().toString()) != null && !ipMacMapping.get
                            (arpHeader.getDstHardwareAddr().toString()).equals(arpHeader.getDstProtocolAddr()
                            .getHostAddress())) {
                        arpwriter.println(packet.getTimestamp() + "," + ethernetPacket.getHeader().getSrcAddr()
                                .toString() + "," +
                                ethernetPacket.getHeader().getDstAddr().toString() + "," +
                                arpHeader.getSrcHardwareAddr() + "," +
                                arpHeader.getSrcProtocolAddr() + "," +
                                arpHeader.getDstHardwareAddr() + "," +
                                arpHeader.getDstProtocolAddr() );
                    }
                }

            } catch (IllegalRawDataException e) {
                e.printStackTrace();
            }


        } else if (packet.getEthType() != null && (packet.getEthType().equals(Constants.ETH_TYPE_IPV4) || packet
                .getEthType().equals(Constants
                .ETH_TYPE_IPV6))) {

            OFFlow ofFlow = null;
            if (deviceFlowMapHolder.get(packet.getSrcMac()) != null) {
                ofFlow = getMatchingFlow(packet, deviceFlowMapHolder.get(packet.getSrcMac()));
            }

            if (ofFlow == null && deviceFlowMapHolder.get(packet.getDstMac()) != null) {
                ofFlow = getMatchingFlow(packet, deviceFlowMapHolder.get(packet.getDstMac()));
            }

            if (ofFlow != null) {

                OFFlow ofFlowx = ofFlow.copy();
                EntropyData entropy10000 = entropy10000Data.get(deviceMac).get(ofFlow);
                EntropyData entropy5000 = entropy5000Data.get(deviceMac).get(ofFlow);
                EntropyData entropy1000 = entropy1000Data.get(deviceMac).get(ofFlow);

                if (monitorFlows) {
                    EntropyHold entropyHold = entropyHoldMap.get(ofFlowx.getName());
                    if (entropyHold == null) {
                        entropyHoldMap.put(ofFlowx.getName(), new EntropyHold(ofFlow.copy()));
                        entropyHold = entropyHoldMap.get(ofFlowx.getName());
                    }
                    entropyHold.addFlow(packet);
                }

                entropy10000.addSrcIp(packet.getSrcIp());
                entropy10000.addDstIp(packet.getDstIp());
                entropy10000.addSrcPort(packet.getSrcPort());
                entropy10000.addDstPort(packet.getDstPort());
                entropy10000.addIcmpCode(packet.getIcmpCode());
                entropy10000.addIcmpType(packet.getIcmpType());

                entropy5000.addSrcIp(packet.getSrcIp());
                entropy5000.addDstIp(packet.getDstIp());
                entropy5000.addSrcPort(packet.getSrcPort());
                entropy5000.addDstPort(packet.getDstPort());
                entropy5000.addIcmpCode(packet.getIcmpCode());
                entropy5000.addIcmpType(packet.getIcmpType());

                entropy1000.addSrcIp(packet.getSrcIp());
                entropy1000.addDstIp(packet.getDstIp());
                entropy1000.addSrcPort(packet.getSrcPort());
                entropy1000.addDstPort(packet.getDstPort());
                entropy1000.addIcmpCode(packet.getIcmpCode());
                entropy1000.addIcmpType(packet.getIcmpType());

                //tmp fix for chromecast
                if (skipFlowsChromecast) {
                    if ((packet.getSrcPort().equals("53") && packet.getSrcIp().equals("8.8.8.8")) ||
                            (packet.getDstPort().equals("53") && packet.getDstIp().equals("8.8.8.8")) ||
                            packet.getSrcPort().equals("123") || packet.getDstPort().equals("123")) {
                        chromecastPacketLog.add(packet);
                        return;
                    }
                }

                if (ofFlowx.getSrcIp().equals("*")) {
                    ofFlowx.setSrcIp(packet.getSrcIp());
                }

                if (ofFlowx.getDstIp().equals("*")) {
                    ofFlowx.setDstIp(packet.getDstIp());
                }

                if (ofFlowx.getIpProto() != null && (ofFlowx.getIpProto().equals(Constants.TCP_PROTO) || ofFlowx
                        .getIpProto().equals(Constants.UDP_PROTO))) {
                    if (ofFlowx.getSrcPort().equals("*")) {
                        ofFlowx.setSrcPort(packet.getSrcPort());

                    }

                    if (ofFlowx.getDstPort().equals("*")) {
                        ofFlowx.setDstPort(packet.getDstPort());

                    }

                } else if (ofFlowx.getIpProto() != null && ofFlowx.getIpProto().equals(Constants.ICMP_PROTO)) {

                    if (ofFlowx.getIcmpCode().equals("*")) {
                        ofFlowx.setIcmpCode(packet.getIcmpCode());
                    }

                    if (ofFlowx.getIcmpType().equals("*")) {
                        ofFlowx.setIcmpType(packet.getIcmpType());
                    }
                }
                ofFlowx.setIdleTimeOut(4 * 60 * 1000); // 4mins
//                ofFlowx.setIdleTimeOut(70 * 1000);
                ofFlowx.setPriority(ofFlow.getPriority() + 1);
                ofFlowx.setPacketCount(1);
                ofFlowx.setVolumeTransmitted(packet.getSize());
                ofFlowx.setOfAction(OFFlow.OFAction.NORMAL);
                OFController.getInstance().addFlow(dpId, ofFlowx);
            }
            //icmp/udp/tcp

            //other ip protocol.

        }



    }



    private OFFlow getMatchingFlow(SimPacket packet, List<OFFlow> ofFlows) {
        for (int i = 0; i < ofFlows.size(); i++) {
            OFFlow flow = ofFlows.get(i);
            String srcMac = packet.getSrcMac();
            String dstMac = packet.getDstMac();
            String ethType = packet.getEthType();
            String vlanId = "*";
            String srcIp = packet.getSrcIp() == null ? "*" : packet.getSrcIp();
            String dstIp = packet.getDstIp() == null ? "*" : packet.getDstIp();
            String ipProto = packet.getIpProto() == null ? "*" : packet.getIpProto();
            String srcPort = packet.getSrcPort() == null ? "*" : packet.getSrcPort();
            String dstPort = packet.getDstPort() == null ? "*" : packet.getDstPort();

            boolean ipMatching ;
            if (flow.getSrcIp().contains("/")) {
                String ip = flow.getSrcIp().split("/")[0];
                if (flow.getSrcIp().equals(Constants.LINK_LOCAL_MULTICAST_IP_RANGE)) {
                    ip = "ff";
                }
                ipMatching = srcIp.startsWith(ip) || flow.getSrcIp().equals("*");
            } else {
                ipMatching = (srcIp.equals(flow.getSrcIp())  || flow.getSrcIp().equals("*"));
            }
            if (flow.getDstIp()!=null) {
                if (flow.getDstIp().contains("/")) {
                    String ip = flow.getDstIp().split("/")[0];
                    if (flow.getDstIp().equals(Constants.LINK_LOCAL_MULTICAST_IP_RANGE)) {
                        ip = "ff";
                    }
                    ipMatching = ipMatching && dstIp.startsWith(ip) || flow.getDstIp().equals("*");
                } else {
                    ipMatching = ipMatching && (dstIp.equals(flow.getDstIp()) || flow.getDstIp().equals("*"));
                }
            }

            boolean condition = (srcMac.equals(flow.getSrcMac()) || flow.getSrcMac().equals("*")) &&
                    (dstMac.equals(flow.getDstMac()) || flow.getDstMac().equals("*")) &&
                    (ethType.equals(flow.getEthType()) || flow.getEthType().equals("*")) &&
                    (vlanId.equals(flow.getVlanId()) || flow.getVlanId().equals("*")) &&
                    ipMatching &&
                    (ipProto.equals(flow.getIpProto()) || flow.getIpProto().equals("*")) &&
                    (srcPort.equals(flow.getSrcPort()) || flow.getSrcPort().equals("*")) &&
                    (dstPort.equals(flow.getDstPort()) || flow.getDstPort().equals("*"));

            if (condition) {
                return flow;
            }
        }
        return null;
    }

    @Override
    public void complete() {
        if (!enabled) {
            return;
        }
        try {
            writeEntropyRaw(entropy10000String, entropy10000filename);
            writeEntropyRaw(entropy5000String, entropy5000filename);
            writeEntropyRaw(entropy1000String, entropy1000filename);
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            writeFlowRaw(flowCounterdata);
            writeFlowCounterRaw(flowSizedata);
        } catch (IOException e) {
            e.printStackTrace();
        }
        arpwriter.close();

    }

    private void addMudConfigs(String mudPayload, String deviceMac, String switchMac) throws IOException {
        DeviceMUDFlowMap deviceMUDFlowMap = processMUD(deviceMac, switchMac, mudPayload);
        List<OFFlow> ofFlows = new ArrayList<>();
        List<OFFlow> monitoringOfFlows = new ArrayList<>();
        if (deviceMUDFlowMap != null) {
            ofFlows.addAll(deviceMUDFlowMap.getFromInternetStaticFlows());
            ofFlows.addAll(deviceMUDFlowMap.getToInternetStaticFlows());
            ofFlows.addAll(deviceMUDFlowMap.getFromLocalStaticFlows());
            ofFlows.addAll(deviceMUDFlowMap.getToLocalStaticFlows());
            ofFlows = sortFlowsWithPriority(ofFlows);
            for (OFFlow ofFlow: ofFlows) {
                if (ofFlow.getPriority() == FIXED_INTERNET_COMMUNICATION ||
                        ofFlow.getPriority() == FIXED_LOCAL_COMMUNICATION ||
                        ofFlow.getPriority() == FIXED_LOCAL_CONTROLLER_COMMUNICATION) {
                    monitoringOfFlows.add(ofFlow);

                }
                OFController.getInstance().addFlow(switchMac, ofFlow);
            }


            deviceFlowMapHolder.put(deviceMac, monitoringOfFlows);
        }
    }


    private List<OFFlow> sortFlowsWithPriority(List<OFFlow> flows) {

        LinkedList<OFFlow> ofFlows = new LinkedList<OFFlow>();

        for (OFFlow flow : flows) {
            boolean exist = false;
            for (int i = 0; i < ofFlows.size(); i++) {
                OFFlow currentFlow = ofFlows.get(i);
                if (currentFlow.equals(flow)) {
                    exist = true;
                }
            }

            if (!exist) {
                if (ofFlows.size() == 0) {
                    ofFlows.add(flow);
                    continue;
                }
                for (int i = 0; i < ofFlows.size(); i++) {
                    OFFlow currentFlow = ofFlows.get(i);

                    if (flow.getPriority() >= currentFlow.getPriority()) {
                        if (i == 0) {
                            ofFlows.addFirst(flow);
                            break;
                        } else {
                            ofFlows.add(i, flow);
                            break;
                        }
                    } else if (i == ofFlows.size() - 1) {
                        ofFlows.addLast(flow);
                        break;
                    }
                }

            }
        }
        return ofFlows;
    }


    private DeviceMUDFlowMap processMUD(String deviceMac, String switchMac, String mudPayload) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        MudSpec mudSpec = mapper.readValue(mudPayload, MudSpec.class);
        DeviceMUDFlowMap deviceMUDFlowMap = loadMudSpec(deviceMac, switchMac, mudSpec);
        installInternetNetworkRules(deviceMac, switchMac, deviceMUDFlowMap);
        installLocalNetworkRules(deviceMac, switchMac, deviceMUDFlowMap);
        return deviceMUDFlowMap;
    }

    private DeviceMUDFlowMap loadMudSpec(String deviceMac, String switchMac, MudSpec mudSpec) {
        List<String> fromDevicePolicyNames = new ArrayList<>();
        List<String> toDevicePolicyNames = new ArrayList<>();
        for (AccessDTO accessDTO : mudSpec.getIetfMud().getFromDevicePolicy().getAccessList().getAccessDTOList()) {
            fromDevicePolicyNames.add(accessDTO.getName());
        }

        for (AccessDTO accessDTO : mudSpec.getIetfMud().getToDevicePolicy().getAccessList().getAccessDTOList()) {
            toDevicePolicyNames.add(accessDTO.getName());
        }

        List<OFFlow> fromInternetFlows = new ArrayList<>();
        List<OFFlow> toInternetFlows = new ArrayList<>();
        List<OFFlow> fromLocalStaticFlows = new ArrayList<>();
        List<OFFlow> toLocalStaticFlows = new ArrayList<>();

        for (AccessControlListHolder accessControlListHolder : mudSpec.getAccessControlList().getAccessControlListHolder()) {
            if (fromDevicePolicyNames.contains(accessControlListHolder.getName())) {
                for (Ace ace : accessControlListHolder.getAces().getAceList()) {
                    Match match = ace.getMatches();

                    //filter local
                    if (match.getIetfMudMatch() != null && (match.getIetfMudMatch().getController() != null
                            || match.getIetfMudMatch().getLocalNetworks() != null)) {

                        //install local network related rules here
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setSrcMac(deviceMac);
                        String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
                                .getEtherType();
                        ofFlow.setEthType(etherType);
                        ofFlow.setPriority(FIXED_LOCAL_COMMUNICATION);
                        if (match.getIpv4Match() != null &&
                                match.getIpv4Match().getProtocol() != 0) {

                            ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                            ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
                        }

                        if (match.getIpv6Match() != null) {
                            ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
                            ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
                        }

                        if (match.getEthMatch() != null) {
                            if (match.getEthMatch().getEtherType() != null) {
                                ofFlow.setEthType(match.getEthMatch().getEtherType());
                            }
                            if (match.getEthMatch().getSrcMacAddress() != null) {
                                ofFlow.setSrcMac(match.getEthMatch().getSrcMacAddress());
                            }
                            if (match.getEthMatch().getDstMacAddress() != null) {
                                ofFlow.setDstMac(match.getEthMatch().getDstMacAddress());
                            }

                        }

                        if (!ofFlow.getEthType().equals(EtherType.IPV4.name()) &&
                                !ofFlow.getEthType().equals(EtherType.IPV6.name())) {
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, ofFlow.getEthType(), "All"));

                        } else {
                            IpNumber ipn = IpNumber.getInstance(Byte.parseByte(ofFlow.getIpProto()));
                            String name = ipn.name().equals("unknown") ? ipn.valueAsString() : ipn.name();
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, name, "All"));
                        }

                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV4.valueAsString())) {
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, IpNumber.ICMPV4.name(), "All"));
                        }

                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV6.valueAsString())) {
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, IpNumber.ICMPV6.name(), "All"));
                        }


                        //tcp
                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getDestinationPortMatch() != null
                                && match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, IpNumber.TCP.name(), match.getTcpMatch()
                                    .getDestinationPortMatch().getPort()));

                        }

                        if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null
                                && match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());

                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, IpNumber.TCP.name(), match.getTcpMatch()
                                    .getSourcePortMatch().getPort()));
                        }
                        //udp
                        if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null
                                && match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, IpNumber.UDP.name(), match.getUdpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null
                                && match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, IpNumber.UDP.name(), match.getUdpMatch()
                                    .getSourcePortMatch().getPort()));
                        }

                        if ((match.getIpv4Match() != null && match.getIpv4Match().getDestinationIp() != null)) {
                            ofFlow.setDstIp(match.getIpv4Match().getDestinationIp());
                            ofFlow.setName(ofFlow.getName() + IP_TAG + match.getIpv4Match().getDestinationIp());
                        } else if (match.getIpv6Match() != null && match.getIpv6Match().getDestinationIp() != null) {
                            ofFlow.setDstIp(match.getIpv6Match().getDestinationIp());
                            ofFlow.setName(ofFlow.getName() + IP_TAG + match.getIpv6Match().getDestinationIp());
                        } else if (match.getIetfMudMatch().getController() != null &&
                                (match.getIetfMudMatch().getController().contains(MUD_URN))) {
                            ofFlow.setDstIp(gatewayIp);
                            ofFlow.setPriority(FIXED_LOCAL_CONTROLLER_COMMUNICATION);
                            ofFlow.setName(ofFlow.getName() + IP_TAG + match.getIetfMudMatch().getController());
                        }

                        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
                        toLocalStaticFlows.add(ofFlow);

                    } else {
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setSrcMac(deviceMac);
                        ofFlow.setDstMac(switchMac);

                        String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
                                .getEtherType();
                        ofFlow.setEthType(etherType);
                        if (match.getIpv4Match() != null &&
                                match.getIpv4Match().getProtocol() != 0) {
                            ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                            ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
                        }

                        if (match.getIpv6Match() != null) {
                            ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
                            ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
                        }



                        if (!ofFlow.getEthType().equals(EtherType.IPV4.name()) &&
                                !ofFlow.getEthType().equals(EtherType.IPV6.name())) {
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, ofFlow.getEthType(), "All"));

                        } else {
                            IpNumber ipn = IpNumber.getInstance(Byte.parseByte(ofFlow.getIpProto()));
                            String name = ipn.name().equals("unknown") ? ipn.valueAsString() : ipn.name();
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, name, "All"));
                        }

                        // name
                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV4.valueAsString())) {
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, IpNumber.ICMPV4.name(), "All"));
                        }

                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV6.valueAsString())) {
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, IpNumber.ICMPV6.name(), "All"));
                        }

                        //tcp
                        if (match.getTcpMatch() != null && match.getTcpMatch().getDestinationPortMatch() != null
                                && match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, IpNumber.TCP.name(), match.getTcpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null
                                && match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, IpNumber.TCP.name(), match.getTcpMatch()
                                    .getSourcePortMatch().getPort()));
                        }
                        //udp
                        if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null
                                && match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, IpNumber.UDP.name(), match
                                    .getUdpMatch()
                                    .getDestinationPortMatch().getPort()));

                        }

                        if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null
                                && match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, IpNumber.UDP.name(), match.getUdpMatch()
                                    .getSourcePortMatch().getPort()));
                        }

                        if (match.getIpv4Match() != null && match.getIpv4Match().getDestinationIp() != null) {
                            ofFlow.setDstIp(match.getIpv4Match().getDestinationIp());
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                            ofFlow.setName(ofFlow.getName() + IP_TAG + match.getIpv4Match().getDestinationIp());
                        } else if (match.getIpv4Match() != null && match.getIpv4Match().getDstDnsName() != null) {
                            ofFlow.setDstIp("*");
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                        } else if (match.getIpv6Match() != null &&
                                match.getIpv6Match().getDestinationIp() != null) {
                            ofFlow.setDstIp(match.getIpv6Match().getDestinationIp());
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                            ofFlow.setName(ofFlow.getName() + IP_TAG + match.getIpv6Match().getDestinationIp());
                        } else if (match.getIpv6Match() != null &&
                                match.getIpv6Match().getDstDnsName() != null) {
                            ofFlow.setDstIp("*");
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                        } else {
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                        }
                        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
                        toInternetFlows.add(ofFlow);

                    }
                }
            } else if (toDevicePolicyNames.contains(accessControlListHolder.getName())) {

                for (Ace ace : accessControlListHolder.getAces().getAceList()) {
                    Match match = ace.getMatches();

                    //filter local
                    if (match.getIetfMudMatch() != null && (match.getIetfMudMatch().getController() != null
                            || match.getIetfMudMatch().getLocalNetworks() != null)) {
                        //install local network related rules here
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setDstMac(deviceMac);
                        ofFlow.setPriority(FIXED_LOCAL_COMMUNICATION);
                        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);

                        if (match.getIpv4Match() != null &&
                                match.getIpv4Match().getProtocol() != 0) {
                            ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
                            ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        }

                        if (match.getIpv6Match() != null) {
                            ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
                            ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
                        }



                        if (!ofFlow.getEthType().equals(EtherType.IPV4.name()) &&
                                !ofFlow.getEthType().equals(EtherType.IPV6.name())) {
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, ofFlow.getEthType(), "All"));

                        } else {
                            IpNumber ipn = IpNumber.getInstance(Byte.parseByte(ofFlow.getIpProto()));
                            String name = ipn.name().equals("unknown") ? ipn.valueAsString() : ipn.name();
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, name, "All"));
                        }

                        // name
                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV4.valueAsString())) {
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, IpNumber.ICMPV4.name(), "All"));
                        }

                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV6.valueAsString())) {
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, IpNumber.ICMPV6.name(), "All"));
                        }

                        //tcp
                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getDestinationPortMatch() != null
                                && match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, IpNumber.TCP.name(), match.getTcpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getSourcePortMatch() != null
                                && match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, IpNumber.TCP.name(), match.getTcpMatch()
                                    .getSourcePortMatch().getPort()));
                        }
                        //udp
                        if (match.getUdpMatch() != null &&
                                match.getUdpMatch().getDestinationPortMatch() != null
                                && match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, IpNumber.UDP.name(), match.getUdpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getUdpMatch() != null &&
                                match.getUdpMatch().getSourcePortMatch() != null
                                && match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
                            if (ofFlow.getSrcPort().equals(Constants.DNS_PORT)) {
                                ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
                            }
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, IpNumber.UDP.name(), match.getUdpMatch()
                                    .getSourcePortMatch().getPort()));
                        }


                        if ((match.getIpv4Match() != null && match.getIpv4Match().getSourceIp() != null)) {
                            ofFlow.setSrcIp(match.getIpv4Match().getSourceIp());
                            ofFlow.setName(ofFlow.getName() + IP_TAG + match.getIpv4Match().getSourceIp());
                        } else if (match.getIpv6Match() != null && match.getIpv6Match().getSourceIp() != null) {
                            ofFlow.setSrcIp(match.getIpv6Match().getSourceIp());
                            ofFlow.setName(ofFlow.getName() + IP_TAG + match.getIpv6Match().getSourceIp());
                        } else if (match.getIetfMudMatch().getController() != null &&
                                (match.getIetfMudMatch().getController().contains(MUD_URN))) {
                            ofFlow.setSrcIp(gatewayIp);
                            ofFlow.setPriority(FIXED_LOCAL_CONTROLLER_COMMUNICATION);
                            ofFlow.setName(ofFlow.getName() + IP_TAG + match.getIetfMudMatch().getController());
                        }
                        fromLocalStaticFlows.add(ofFlow);
                    } else {
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setSrcMac(switchMac);
                        ofFlow.setDstMac(deviceMac);
                        String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
                                .getEtherType();
                        ofFlow.setEthType(etherType);
                        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
                        if (match.getIpv4Match() != null &&
                                match.getIpv4Match().getProtocol() != 0) {

                            ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                            ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
                        }

                        if (match.getIpv6Match() != null) {
                            ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
                            ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
                        }

                        if (!ofFlow.getEthType().equals(EtherType.IPV4.name()) &&
                                !ofFlow.getEthType().equals(EtherType.IPV6.name())) {
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, ofFlow.getEthType(), "All"));

                        } else {
                            IpNumber ipn = IpNumber.getInstance(Byte.parseByte(ofFlow.getIpProto()));
                            String name = ipn.name().equals("unknown") ? ipn.valueAsString() : ipn.name();
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, name, "All"));
                        }

                        // name
                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV4.valueAsString())) {
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, IpNumber.ICMPV4.name(), "All"));
                        }

                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV6.valueAsString())) {
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, IpNumber.ICMPV6.name(), "All"));
                        }

                        //tcp
                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getDestinationPortMatch() != null
                                && match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, IpNumber.TCP.name(), match.getTcpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getSourcePortMatch() != null
                                && match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, IpNumber.TCP.name(), match.getTcpMatch()
                                    .getSourcePortMatch().getPort()));
                        }
                        //udp
                        if (match.getUdpMatch() != null &&
                                match.getUdpMatch().getDestinationPortMatch() != null
                                && match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, IpNumber.UDP.name(), match
                                    .getUdpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getUdpMatch() != null &&
                                match.getUdpMatch().getSourcePortMatch() != null
                                && match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
                            if (ofFlow.getSrcPort().equals(Constants.DNS_PORT)) {
                                ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
                            }
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, IpNumber.UDP.name(), match.getUdpMatch()
                                    .getSourcePortMatch().getPort()));
                        }

                        if (match.getIpv4Match() != null && match.getIpv4Match().getSourceIp() != null) {
                            ofFlow.setSrcIp(match.getIpv4Match().getSourceIp());
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                            ofFlow.setName(ofFlow.getName() + IP_TAG + match.getIpv4Match().getSourceIp());
                        } else if (match.getIpv4Match() != null && match.getIpv4Match().getSrcDnsName() != null) {
                            ofFlow.setSrcIp("*");
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                        } else if (match.getIpv6Match() != null && match.getIpv6Match().getSourceIp() != null) {
                            ofFlow.setSrcIp(match.getIpv6Match().getSourceIp());
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                            ofFlow.setName(ofFlow.getName() + IP_TAG + match.getIpv6Match().getSourceIp());
                        } else if (match.getIpv6Match() != null && match.getIpv6Match().getSrcDnsName() != null) {
                            ofFlow.setSrcIp("*");
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                        } else {
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                        }
                        fromInternetFlows.add(ofFlow);
                    }
                }
            }
        }

        DeviceMUDFlowMap deviceFlowMap = new DeviceMUDFlowMap();
//        deviceFlowMap.setFromInternetDynamicFlows(fromInternetDynamicFlows);
        deviceFlowMap.setFromInternetStaticFlows(fromInternetFlows);
//        deviceFlowMap.setToInternetDynamicFlows(toInternetDynamicFlows);
        deviceFlowMap.setToInternetStaticFlows(toInternetFlows);
        deviceFlowMap.setToLocalStaticFlows(toLocalStaticFlows);
        deviceFlowMap.setFromLocalStaticFlows(fromLocalStaticFlows);
        return deviceFlowMap;

    }

    private void installLocalNetworkRules(String deviceMac, String switchMac, DeviceMUDFlowMap deviceMUDFlowMap) {
        OFFlow ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_ARP);
        ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        deviceMUDFlowMap.getToLocalStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_ARP);
        ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setIpProto(Constants.ICMP_PROTO);
        ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac("14:cc:20:51:33:e9");
        ofFlow.setEthType("0x888e");
        ofFlow.setPriority(100);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setSrcMac("14:cc:20:51:33:e9");
        ofFlow.setEthType("0x888e");
        ofFlow.setPriority(100);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setIpProto(Constants.TCP_PROTO);
        ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setIpProto(Constants.UDP_PROTO);
        ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);


        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setIpProto(Constants.ICMP_PROTO);
        ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setIpProto(Constants.TCP_PROTO);
        ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setIpProto(Constants.UDP_PROTO);
        ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);
    }

    private void installInternetNetworkRules(String deviceMac, String switchMac, DeviceMUDFlowMap deviceMUDFlowMap) {

        OFFlow ofFlow = new OFFlow();
        ofFlow.setSrcMac(switchMac);
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setIpProto(Constants.TCP_PROTO);
        ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getFromInternetStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(switchMac);
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setIpProto(Constants.UDP_PROTO);
        ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getFromInternetStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac(switchMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setIpProto(Constants.ICMP_PROTO);
        ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getToInternetStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac(switchMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setIpProto(Constants.UDP_PROTO);
        ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getToInternetStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac(switchMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setIpProto(Constants.TCP_PROTO);
        ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getToInternetStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(switchMac);
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setIpProto(Constants.ICMP_PROTO);
        ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getFromInternetStaticFlows().add(ofFlow);

    }

    private static void writeEntropyRaw(List<String> records, String entropyfilename) throws IOException {
        File file = new File(entropyfilename);
        FileWriter writer = new FileWriter(file, true);
        System.out.println("Writing raw... ");
        write(records, writer);

    }

    private void writeFlowRaw(List<String> records) throws IOException {
        File file = new File(flowcounterfilename);
        FileWriter writer = new FileWriter(file, true);
        System.out.println("Writing raw... ");
        write(records, writer);

    }

    private void writeFlowCounterRaw(List<String> records) throws IOException {
        File file = new File(flowSizefilename);
        FileWriter writer = new FileWriter(file, true);
        System.out.println("Writing raw... ");
        write(records, writer);

    }

    private static void write(List<String> records, Writer writer) throws IOException {
        for (String record: records) {
            writer.write(record + "\n");
        }
        writer.flush();
        writer.close();
    }

    private void buildVolumeData(long timestamp) {
        List<OFFlow> tempflowStats = new ArrayList<>();
        List<OFFlow> flowStats = OFController.getInstance().getAllFlows(switchMac);
        for (OFFlow ofFlow : flowStats) {
            if (!ofFlow.getSrcMac().equals(deviceMac) && !ofFlow.getDstMac().equals(deviceMac)) {
                continue;
            }
            int priority = ofFlow.getPriority() - 1;
            if (priority == FIXED_INTERNET_COMMUNICATION || priority == FIXED_LOCAL_COMMUNICATION ||
                    priority == FIXED_LOCAL_CONTROLLER_COMMUNICATION) {
                OFFlow ofFlowx = ofFlow.copy();
                ofFlowx.setPacketCount(ofFlow.getPacketCount());
                ofFlowx.setVolumeTransmitted(ofFlow.getVolumeTransmitted());
                tempflowStats.add(ofFlowx);

                if (!lastFlow.contains(ofFlow)) {

                    flowCounterdata.add(timestamp + "," + ofFlow.getName() +"," + ofFlow.getPacketCount() +"," + ofFlow
                            .getVolumeTransmitted() + "," + ofFlow.getFlowStringWithoutFlowStat().replace(",", "|"));

                } else {


                    for (Iterator<OFFlow> it = lastFlow.iterator(); it.hasNext(); ) {
                        OFFlow f = it.next();
                        if (f.equals(ofFlow)){
                            flowCounterdata.add(timestamp + "," + ofFlow.getName() +","+
                                    (ofFlow.getPacketCount() - f.getPacketCount()) +","
                                    + (ofFlow.getVolumeTransmitted() - f.getVolumeTransmitted())
                                    + "," + ofFlow.getFlowStringWithoutFlowStat().replace(",", "|"));
                            break;
                        }
                    }
                }
            }
        }

        //chromecast
        if (skipFlowsChromecast) {
            for (SimPacket packet : chromecastPacketLog) {
                if (packet.getSrcPort().equals("53")) {
                    flowCounterdata.add(timestamp + ",FromInternetUDPPort53IP8.8.8.8/32," + 1 + "," + packet.getSize()
                            + "," + packet.getPacketInfoWithoutStas().replace(",", "|"));
                } else if (packet.getDstPort().equals("53")) {
                    flowCounterdata.add(timestamp + ",ToInternetUDPPort53IP8.8.8.8/32," + 1 + "," + packet.getSize()
                            + "," + packet.getPacketInfoWithoutStas().replace(",", "|"));
                }
                if (packet.getSrcPort().equals("123")) {
                    flowCounterdata.add(timestamp + ",FromInternetUDPPort123," + 1 + "," + packet.getSize()
                            + "," + packet.getPacketInfoWithoutStas().replace(",", "|"));
                }
                if (packet.getDstPort().equals("123")) {
                    flowCounterdata.add(timestamp + ",ToInternetUDPPort123," + 1 + "," + packet.getSize()
                            + "," + packet.getPacketInfoWithoutStas().replace(",", "|"));
                }


            }
            chromecastPacketLog.clear();
        }
        //endchromecast
        lastFlow.clear();
        lastFlow.addAll(tempflowStats);
    }

}
