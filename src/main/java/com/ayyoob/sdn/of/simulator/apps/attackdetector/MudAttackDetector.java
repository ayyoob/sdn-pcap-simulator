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
    private static final int FIXED_LOCAL_COMMUNICATION = 5;
    private static final int DEFAULT_LOCAL_COMMUNICATION = 4;
    private static final int FIXED_INTERNET_COMMUNICATION = 10;
    private static final int FIXED_LOCAL_CONTROLLER_COMMUNICATION = 15;
    private static final int DEFAULT_INTERNET_COMMUNICATION = 9;
    private static final String MUD_URN = "urn:ietf:params:mud";
    private static String gatewayIp;
    private static Map<String, List<OFFlow>> deviceFlowMapHolder = new HashMap<>();
    private static Map<String, Map<OFFlow,EntropyData >> entropyData = new HashMap<>();
    private static Map<String, String> ipMacMapping = new HashMap<>();
    private String arpfilename;
    private static String entropyfilename;
    private static PrintWriter arpwriter = null;
    private static long summerizationTimeInMillis = 10000;
    private static long flowSummerizationTimeInMillis = 60000;
    private static String FROM_LOCAL_FEATURE_NAME = "FromLocal%sPort%s";
    private static String TO_LOCAL_FEATURE_NAME = "ToLocal%sPort%s";
    private static String FROM_INTERNET_FEATURE_NAME = "FromInternet%sPort%s";
    private static String TO_INTERNET_FEATURE_NAME = "ToInternet%sPort%s";
    private static String IP_TAG = "IP";
    private long lastLogTime = 0;
    private long lastFlowLogTime = 0;
    private List<String> entropyString = new ArrayList<>();
    private List<String> flowCounterdata = new ArrayList<>();
    private static Set<OFFlow> lastFlow = new HashSet<OFFlow>();

    @Override
    public void init(JSONObject jsonObject) {
        enabled = (Boolean) jsonObject.get("enabled");
        if (!enabled) {
            return;
        }
        switchMac = (String) jsonObject.get("dpId");
        gatewayIp = (String) jsonObject.get("gatewayIp");
        deviceMac = (String) jsonObject.get("device");
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

        Map<OFFlow,EntropyData > flowEntropyData = new HashMap<>();
        for (OFFlow ofFlow : deviceFlowMapHolder.get(deviceMac)) {
            flowEntropyData.put(ofFlow, new EntropyData());
        }
        entropyData.put(deviceMac, flowEntropyData);


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
                "_arpspoof"+".csv" ;


        entropyfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") +
                "_entropy"+summerizationTimeInMillis+".csv" ;
        try {
            arpwriter = new PrintWriter(new BufferedWriter(
                    new FileWriter(arpfilename)), true);
        } catch (IOException e) {
            e.printStackTrace();
        }
        arpwriter.print("timestamp");
        for (OFFlow ofFlow : deviceFlowMapHolder.get(deviceMac) ) {
            arpwriter.print(ofFlow.getName()+ "," + ofFlow.getName()+ "," + ofFlow.getName()+ "," + ofFlow.getName()
                    + "," +
                    ofFlow.getName()+ "," + ofFlow.getName()+ ",");
        }
        arpwriter.println();
        arpwriter.print("timestamp");
        for (OFFlow ofFlow : deviceFlowMapHolder.get(deviceMac) ) {
            arpwriter.print("srcMac, dstMac, requestSrcMac, requestSrcIp, requestTargetMac, requestTargetIPMac");
        }
        arpwriter.println();
        flowCounterdata.add("timestamp,flowname,packetcount,bytecount");

    }

    @Override
    public void process(String dpId, long timestamp) {
        if (!enabled) {
            return;
        }
        if (!this.switchMac.equals(dpId)) {
            return;
        }

        long nextLogTime = 0;
        if (lastLogTime == 0) {
            lastLogTime = timestamp;
            return;
        }
        nextLogTime = lastLogTime + summerizationTimeInMillis;
        long currentTime = timestamp;


        while (currentTime >= nextLogTime) {
            entropyString.add(nextLogTime + getEntropyFlowString());
            resetEntropyFlow();
            nextLogTime = nextLogTime + summerizationTimeInMillis;
        }


        lastLogTime = nextLogTime - summerizationTimeInMillis;

        if (entropyString.size() > 10000) {
            try {
                writeRaw(entropyString);
                entropyString.clear();
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
            buildVolumeData(currentTime);
        }

        if (flowCounterdata.size() > 10000) {
            try {
                writeRaw(flowCounterdata);
                flowCounterdata.clear();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private String getEntropyFlowString() {
        String data = "";
        for (OFFlow flow : deviceFlowMapHolder.get(deviceMac)) {
            data = data + "," + entropyData.get(deviceMac).get(flow).calculateShannonEntropy();
        }

        return  data;
    }

    private void resetEntropyFlow() {
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
                    if (!ipMacMapping.get(arpHeader.getSrcHardwareAddr()).equals(arpHeader.getSrcProtocolAddr()
                            .getHostAddress())) {
                        //spoof logger
                        arpwriter.write(ethernetPacket.getHeader().getSrcAddr().toString() + "," +
                                ethernetPacket.getHeader().getDstAddr().toString() + "," +
                                arpHeader.getSrcHardwareAddr() + "," +
                                arpHeader.getSrcProtocolAddr() + "," +
                                arpHeader.getDstHardwareAddr() + "," +
                                arpHeader.getDstProtocolAddr() );
                    } else if (!ipMacMapping.get(arpHeader.getDstHardwareAddr()).equals(arpHeader.getDstProtocolAddr()
                            .getHostAddress())) {
                        arpwriter.write(ethernetPacket.getHeader().getSrcAddr().toString() + "," +
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

            if (ofFlow != null && deviceFlowMapHolder.get(packet.getDstMac()) != null) {
                ofFlow = getMatchingFlow(packet, deviceFlowMapHolder.get(packet.getDstMac()));
            }

            if (ofFlow != null) {

                OFFlow ofFlowx = ofFlow.copy();
                EntropyData entropy = entropyData.get(deviceMac).get(ofFlow);
                if (ofFlowx.getSrcIp().equals("*")) {
                    ofFlowx.setSrcIp(packet.getSrcIp());
                    entropy.addSrcIp(packet.getSrcIp());
                }

                if (ofFlowx.getDstIp().equals("*")) {
                    ofFlowx.setDstIp(packet.getDstIp());
                    entropy.addDstIp(packet.getDstIp());
                }

                if (ofFlowx.getIpProto() != null && (ofFlowx.getIpProto().equals(Constants.TCP_PROTO) || ofFlowx
                        .getIpProto().equals(Constants.UDP_PROTO))) {
                    if (ofFlowx.getSrcPort().equals("*")) {
                        ofFlowx.setSrcPort(packet.getSrcPort());
                        entropy.addSrcPort(packet.getSrcPort());
                    }

                    if (ofFlowx.getDstPort().equals("*")) {
                        ofFlowx.setDstPort(packet.getDstPort());
                        entropy.addDstPort(packet.getDstPort());
                    }

                } else if (ofFlowx.getIpProto() != null && ofFlowx.getIpProto().equals(Constants.ICMP_PROTO)) {

                    if (ofFlowx.getIcmpCode().equals("*")) {
                        ofFlowx.setIcmpCode(packet.getIcmpCode());
                        entropy.addIcmpCode(packet.getIcmpCode());
                    }

                    if (ofFlowx.getIcmpType().equals("*")) {
                        ofFlowx.setIcmpType(packet.getIcmpType());
                        entropy.addIcmpType(packet.getIcmpType());
                    }
                }
                ofFlowx.setIdleTimeOut(4 * 60 * 1000); // 4mins
                ofFlowx.setPriority(ofFlow.getPriority() + 1);

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

            boolean condition = (srcMac.equals(flow.getSrcMac()) || flow.getSrcMac().equals("*")) &&
                    (dstMac.equals(flow.getDstMac()) || flow.getDstMac().equals("*")) &&
                    (ethType.equals(flow.getEthType()) || flow.getEthType().equals("*")) &&
                    (vlanId.equals(flow.getVlanId()) || flow.getVlanId().equals("*")) &&
                    (srcIp.equals(flow.getSrcIp()) || flow.getSrcIp().equals("*")) &&
                    (dstIp.equals(flow.getDstIp()) || flow.getDstIp().equals("*")) &&
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
            writeRaw(entropyString);
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
                if (ofFlow.getPriority() == DEFAULT_INTERNET_COMMUNICATION ||
                        ofFlow.getPriority() == DEFAULT_LOCAL_COMMUNICATION) {
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

                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV4.valueAsString())) {
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, IpNumber.ICMPV4.name(), "All"));
                        }

                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV6.valueAsString())) {
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, IpNumber.ICMPV6.name(), "All"));
                        }
                        if (!ofFlow.getEthType().equals(EtherType.IPV4.name()) &&
                                !ofFlow.getEthType().equals(EtherType.IPV6.name())) {
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, ofFlow.getEthType(), "All"));

                        } else {
                            IpNumber ipn = IpNumber.getInstance(Byte.parseByte(ofFlow.getIpProto()));
                            String name = ipn.name().equals("unknown") ? ipn.valueAsString() : ipn.name();
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, name, "All"));
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

                        // name
                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV4.valueAsString())) {
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, IpNumber.ICMPV4.name(), "All"));
                        }

                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV6.valueAsString())) {
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, IpNumber.ICMPV6.name(), "All"));
                        }

                        if (!ofFlow.getEthType().equals(EtherType.IPV4.name()) &&
                                !ofFlow.getEthType().equals(EtherType.IPV6.name())) {
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, ofFlow.getEthType(), "All"));

                        } else {
                            IpNumber ipn = IpNumber.getInstance(Byte.parseByte(ofFlow.getIpProto()));
                            String name = ipn.name().equals("unknown") ? ipn.valueAsString() : ipn.name();
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, name, "All"));
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

                        // name
                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV4.valueAsString())) {
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, IpNumber.ICMPV4.name(), "All"));
                        }

                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV6.valueAsString())) {
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, IpNumber.ICMPV6.name(), "All"));
                        }

                        if (!ofFlow.getEthType().equals(EtherType.IPV4.name()) &&
                                !ofFlow.getEthType().equals(EtherType.IPV6.name())) {
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, ofFlow.getEthType(), "All"));

                        } else {
                            IpNumber ipn = IpNumber.getInstance(Byte.parseByte(ofFlow.getIpProto()));
                            String name = ipn.name().equals("unknown") ? ipn.valueAsString() : ipn.name();
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, name, "All"));
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

                        // name
                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV4.valueAsString())) {
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, IpNumber.ICMPV4.name(), "All"));
                        }

                        if (ofFlow.getIpProto().equals(IpNumber.ICMPV6.valueAsString())) {
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, IpNumber.ICMPV6.name(), "All"));
                        }

                        if (!ofFlow.getEthType().equals(EtherType.IPV4.name()) &&
                                !ofFlow.getEthType().equals(EtherType.IPV6.name())) {
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, ofFlow.getEthType(), "All"));

                        } else {
                            IpNumber ipn = IpNumber.getInstance(Byte.parseByte(ofFlow.getIpProto()));
                            String name = ipn.name().equals("unknown") ? ipn.valueAsString() : ipn.name();
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, name, "All"));
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

    private static void writeRaw(List<String> records) throws IOException {
        File file = new File(entropyfilename);
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
                tempflowStats.add(ofFlow);

                if (!lastFlow.contains(ofFlow)) {

                    flowCounterdata.add(timestamp + "," + ofFlow.getName() + ofFlow.getPacketCount() +"," + ofFlow
                            .getVolumeTransmitted() + "," + ofFlow.getFlowStringWithoutFlowStat().replace(",", "|"));

                } else {


                    for (Iterator<OFFlow> it = lastFlow.iterator(); it.hasNext(); ) {
                        OFFlow f = it.next();
                        if (f.equals(ofFlow)){
                            flowCounterdata.add(timestamp + "," + ofFlow.getName() +
                                    (ofFlow.getPacketCount() - f.getPacketCount()) +","
                                    + (ofFlow.getVolumeTransmitted() - f.getVolumeTransmitted())
                                    + "," + ofFlow.getFlowStringWithoutFlowStat().replace(",", "|"));
                            break;
                        }
                    }
                }
            }
        }
        lastFlow.clear();
        lastFlow.addAll(tempflowStats);
    }

}
