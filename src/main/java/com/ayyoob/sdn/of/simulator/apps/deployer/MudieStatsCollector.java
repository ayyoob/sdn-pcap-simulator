package com.ayyoob.sdn.of.simulator.apps.deployer;

import com.ayyoob.sdn.of.simulator.Constants;
import com.ayyoob.sdn.of.simulator.OFController;
import com.ayyoob.sdn.of.simulator.OFFlow;
import com.ayyoob.sdn.of.simulator.SimPacket;
import com.ayyoob.sdn.of.simulator.apps.StatListener;
import com.ayyoob.sdn.of.simulator.apps.deployer.mudflowdto.DeviceMUDFlowMap;
import com.ayyoob.sdn.of.simulator.apps.deployer.mudflowdto.MudFeatureWrapper;
import com.ayyoob.sdn.of.simulator.apps.legacydevice.processor.mud.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.simple.JSONObject;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class MudieStatsCollector implements StatListener {

    private static boolean enabled = true;
    private static long summerizationTimeInMillis = 60000;
    private long lastLogTime = 0;
    private String dpId;
    private String deviceMac;
    private static String filename;
    private static final int FIXED_LOCAL_COMMUNICATION = 5;
    private static final int DEFAULT_LOCAL_COMMUNICATION = 4;
    private static final int FIXED_INTERNET_COMMUNICATION = 10;
    private static final int FIXED_LOCAL_CONTROLLER_COMMUNICATION = 11;
    private static final int DEFAULT_INTERNET_COMMUNICATION = 9;
    private static final int DYNAMIC_INTERNET_COMMUNICATION = 15000;
    private static final String MUD_URN = "urn:ietf:params:mud";
    private static String gatewayIp;
    private static String FROM_LOCAL_FEATURE_NAME = "FromLocal%sPort%s";
    private static String TO_LOCAL_FEATURE_NAME = "ToLocal%sPort%s";
    private static String FROM_INTERNET_FEATURE_NAME = "FromInternet%sPort%s";
    private static String TO_INTERNET_FEATURE_NAME = "ToInternet%sPort%s";
    private static String TCP = "Tcp";
    private static String UDP = "Udp";
    private static String ICMP = "Icmp";
    private static String ARP = "Arp";
    private static PrintWriter writer = null;

    private Map<String, DeviceMUDFlowMap> deviceFlowMapHolder = new HashMap<>();
    private Map<String, MudFeatureWrapper> featureSet = new HashMap();

    @Override
    public void init(JSONObject jsonObject) {
        enabled = (Boolean) jsonObject.get("enabled");
        if (!enabled) {
            return;
        }
        summerizationTimeInMillis = ((Long) jsonObject.get("summerizationTimeInSeconds")) * 1000;
        dpId = (String) jsonObject.get("dpId");
        deviceMac = (String) jsonObject.get("deviceMac");
        gatewayIp = (String) jsonObject.get("gatewayIp");
        String mudPath = (String) jsonObject.get("mudPath");
        String currentPath = Paths.get(".").toAbsolutePath().normalize().toString();

        File workingDirectory = new File(currentPath + File.separator + "result");
        if (!workingDirectory.exists()) {
            workingDirectory.mkdir();
        }
        filename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_flowstats"+".csv" ;

        try {
            byte[] encoded = Files.readAllBytes(Paths.get(mudPath));
            String mudPayload = new String(encoded, Charset.defaultCharset());

            addMudConfigs(mudPayload, deviceMac, dpId);

        } catch (IOException e) {
            e.printStackTrace();
        }
        DeviceMUDFlowMap deviceMUDFlowMap = deviceFlowMapHolder.get(deviceMac);
        Set<OFFlow> staticOfflows = new LinkedHashSet<>();
        staticOfflows.addAll(deviceMUDFlowMap.getFromInternetStaticFlows());
        staticOfflows.addAll(deviceMUDFlowMap.getToInternetStaticFlows());
        staticOfflows.addAll(deviceMUDFlowMap.getFromLocalStaticFlows());
        staticOfflows.addAll(deviceMUDFlowMap.getToLocalStaticFlows());

        Set<OFFlow> dynamicOfflows = new LinkedHashSet<>();
        dynamicOfflows.addAll(deviceMUDFlowMap.getFromInternetDynamicFlows());
        dynamicOfflows.addAll(deviceMUDFlowMap.getToInternetDynamicFlows());

        String row = "Timestamp";
        int flowOrder[] = new int[staticOfflows.size() + dynamicOfflows.size()];
        int i =0;

        for (OFFlow ofFlow:staticOfflows) {
            row = row + "," + ofFlow.getName() + "Packet,"+ ofFlow.getName() + "Byte";
            flowOrder[i] = ofFlow.hashCode();
            i++;
        }
        staticOfflows.stream().forEach(ofFlow -> System.out.println(ofFlow.getFlowString() + ","+ ofFlow.getName()));

        for (OFFlow ofFlow:dynamicOfflows) {
            row = row + "," + ofFlow.getName() + "Packet,"+ ofFlow.getName() + "Byte";
            flowOrder[i] = ofFlow.hashCode();
            i++;
        }
        dynamicOfflows.stream().forEach(ofFlow -> System.out.println(ofFlow.getFlowString() + ","+ ofFlow.getName()));
        MudFeatureWrapper mudieFeatureWrapper = new MudFeatureWrapper(staticOfflows, dynamicOfflows);
        mudieFeatureWrapper.setFlowOrder(flowOrder);
        featureSet.put(deviceMac, mudieFeatureWrapper);
        try {
            writer = new PrintWriter(new BufferedWriter(
					new FileWriter(filename)), true);
        } catch (IOException e) {
            e.printStackTrace();
        }
        writer.println(row);
    }

    @Override
    public void process(String dpId, long timestamp) {
        if (!enabled) {
            return;
        }

        if (lastLogTime == 0) {
            lastLogTime = timestamp;
            return;
        }
        long nextLogTime = lastLogTime + summerizationTimeInMillis;

        long currentTime = timestamp;

        if (currentTime >= nextLogTime) {
            lastLogTime = currentTime;
            logDeviceData();
            //data.add(currentTime + "," + getVolumeData());
        }

    }

    private void logDeviceData() {
        List<OFFlow> flowStats = OFController.getInstance().getAllFlows(dpId);
        List<OFFlow> deviceFlowStats = new ArrayList<>();
        for (OFFlow currentFlow : flowStats) {
            if (!currentFlow.getSrcMac().equals(deviceMac) && !currentFlow.getDstMac().equals(deviceMac)) {
                continue;
            }
            deviceFlowStats.add(currentFlow);
        }

        MudFeatureWrapper mudieFeatureWrapper = featureSet.get(deviceMac);
        Map<Integer, OFFlow> currentStaticFlowRecords = new HashMap<>();
        Map<Integer, OFFlow> currentDynamicFlowRecords = new HashMap<>();
        for (OFFlow currentFlow : deviceFlowStats) {
            OFFlow tmpFlow = currentFlow.copy();
            tmpFlow.setPacketCount(currentFlow.getPacketCount());
            tmpFlow.setVolumeTransmitted(currentFlow.getVolumeTransmitted());
            currentFlow = tmpFlow;
            if (mudieFeatureWrapper.getLastStaticFlowRecords() == null) {
                OFFlow flow = mudieFeatureWrapper.getStaticFlows().get(currentFlow.hashCode());
                if (flow != null) {
                    currentStaticFlowRecords.put(currentFlow.hashCode(), currentFlow);
                } else {
                    flow = getMatchingFlow(currentFlow, mudieFeatureWrapper.getDynamicFlows());
                    if (flow == null) {
                        continue;
                    }

                    currentDynamicFlowRecords.put(currentFlow.hashCode(), currentFlow);
                }

            } else {
                OFFlow flow = mudieFeatureWrapper.getStaticFlows().get(currentFlow.hashCode());
                if (flow != null) {
                    OFFlow lastFlowRecord = mudieFeatureWrapper.getLastStaticFlowRecords().get(currentFlow.hashCode());
                    if (lastFlowRecord != null && currentFlow.getPacketCount() - lastFlowRecord.getPacketCount() >= 0) {
                        flow.setPacketCount(currentFlow.getPacketCount() - lastFlowRecord.getPacketCount());
                        flow.setVolumeTransmitted(currentFlow.getVolumeTransmitted() - lastFlowRecord.getVolumeTransmitted());
                    } else {
                        flow.setPacketCount(currentFlow.getPacketCount());
                        flow.setVolumeTransmitted(currentFlow.getVolumeTransmitted());
                    }
                    currentStaticFlowRecords.put(currentFlow.hashCode(),currentFlow);
                } else {
                    flow = getMatchingFlow(currentFlow, mudieFeatureWrapper.getDynamicFlows());
                    if (flow == null) {
                        continue;
                    }
                    OFFlow lastFlowRecord = getMatchingFlow(currentFlow,mudieFeatureWrapper.getLastReactiveFlowRecords());
                    if (lastFlowRecord!= null && currentFlow.getPacketCount() - lastFlowRecord.getPacketCount() >= 0) {
                        flow.setPacketCount(flow.getPacketCount() + currentFlow.getPacketCount() - lastFlowRecord.getPacketCount());
                        flow.setVolumeTransmitted(flow.getVolumeTransmitted() + currentFlow.getVolumeTransmitted()
                                - lastFlowRecord.getVolumeTransmitted());
                    } else {
                        flow.setPacketCount(flow.getPacketCount() + currentFlow.getPacketCount());
                        flow.setVolumeTransmitted(flow.getVolumeTransmitted() + currentFlow.getVolumeTransmitted());
                    }
                    currentDynamicFlowRecords.put(currentFlow.hashCode(), currentFlow);
                }
            }
        }

        if (mudieFeatureWrapper.getLastStaticFlowRecords() != null) {
            //log data here.
            publishData(mudieFeatureWrapper);
            mudieFeatureWrapper.resetDynamicFlowMetrics();

        }
        mudieFeatureWrapper.setLastStaticFlowRecords(currentStaticFlowRecords);
        mudieFeatureWrapper.setLastReactiveFlowRecords(currentDynamicFlowRecords);
    }

    private void publishData(MudFeatureWrapper mudieFeatureWrapper) {
        String row =  "" + lastLogTime;
        for(int key : mudieFeatureWrapper.getFlowOrder()) {
            if (mudieFeatureWrapper.getStaticFlows().containsKey(key)) {
                row = row + "," + mudieFeatureWrapper.getStaticFlows().get(key).getPacketCount()
                        + "," + mudieFeatureWrapper.getStaticFlows().get(key).getVolumeTransmitted();
            } else {
                row = row + "," + mudieFeatureWrapper.getDynamicFlows().get(key).getPacketCount()
                        + "," + mudieFeatureWrapper.getDynamicFlows().get(key).getVolumeTransmitted();
            }

        }

        writer.println(row);
    }


    @Override
    public void complete() {
        if (!enabled) {
            return;
        }
        writer.close();
    }


    private void addMudConfigs(String mudPayload, String deviceMac, String switchMac) throws IOException {
        DeviceMUDFlowMap deviceMUDFlowMap = processMUD(deviceMac, switchMac, mudPayload);
        if (deviceMUDFlowMap != null) {
            deviceFlowMapHolder.put(deviceMac, deviceMUDFlowMap);
        }
    }

    private DeviceMUDFlowMap processMUD(String deviceMac, String switchMac, String mudPayload) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        MudSpec mudSpec = mapper.readValue(mudPayload, MudSpec.class);
        DeviceMUDFlowMap deviceMUDFlowMap = loadMudSpec(deviceMac, switchMac, mudSpec);
        installInternetNetworkRules(deviceMac, switchMac, deviceMUDFlowMap);
        installLocalNetworkRules(deviceMac, deviceMUDFlowMap);
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

        List<OFFlow> fromInternetDynamicFlows = new ArrayList<>();
        List<OFFlow> toInternetDynamicFlows = new ArrayList<>();
        List<OFFlow> fromInternetStaticFlows = new ArrayList<>();
        List<OFFlow> toInternetStaticFlows = new ArrayList<>();
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

                        if (ofFlow.getIpProto().equals(Constants.ICMP_PROTO)) {
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, ICMP, "All"));
                        }

                        if (!ofFlow.getEthType().equals(Constants.ETH_TYPE_IPV4) &&
                                !ofFlow.getEthType().equals(Constants.ETH_TYPE_IPV6)) {
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, ofFlow.getEthType(), "All"));

                        } else {
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, getProto(ofFlow.getIpProto()), "All"));
                        }

                        //tcp
                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getDestinationPortMatch() != null
                                && match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, TCP, match.getTcpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null
                                && match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, TCP, match.getTcpMatch()
                                    .getSourcePortMatch().getPort()));
                        }
                        //udp
                        if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null
                                && match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, UDP, match.getUdpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null
                                && match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, UDP, match.getUdpMatch()
                                    .getSourcePortMatch().getPort()));
                        }

                        if ((match.getIpv4Match() != null && match.getIpv4Match().getDestinationIp() != null)) {
                            ofFlow.setDstIp(match.getIpv4Match().getDestinationIp());
                            ofFlow.setName(ofFlow.getName() + "IP" + match.getIpv4Match().getDestinationIp());
                        } else if (match.getIpv6Match() != null && match.getIpv6Match().getDestinationIp() != null) {
                            ofFlow.setName(ofFlow.getName() + "IP" + match.getIpv6Match().getDestinationIp());
                            ofFlow.setDstIp(match.getIpv6Match().getDestinationIp());
                        } else if (match.getIetfMudMatch().getController() != null &&
                                (match.getIetfMudMatch().getController().contains(MUD_URN))) {
                            ofFlow.setDstIp(gatewayIp);
                            ofFlow.setPriority(FIXED_LOCAL_CONTROLLER_COMMUNICATION);
                            ofFlow.setName(ofFlow.getName() + "IP" + gatewayIp);
                        }

                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
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

                        if (ofFlow.getIpProto().equals(Constants.ICMP_PROTO)) {
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, ICMP, "All"));
                        }

                        if (!ofFlow.getEthType().equals(Constants.ETH_TYPE_IPV4) &&
                                !ofFlow.getEthType().equals(Constants.ETH_TYPE_IPV6)) {
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, ofFlow.getEthType(), "All"));

                        } else {
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, getProto(getProto(ofFlow.getIpProto())), "All"));
                        }


                        //tcp
                        if (match.getTcpMatch() != null && match.getTcpMatch().getDestinationPortMatch() != null
                                && match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, TCP, match.getTcpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null
                                && match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, TCP, match.getTcpMatch()
                                    .getSourcePortMatch().getPort()));
                        }
                        //udp
                        if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null
                                && match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, UDP, match.getUdpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null
                                && match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, UDP, match.getUdpMatch()
                                    .getSourcePortMatch().getPort()));
                        }

                        if (match.getIpv4Match() != null && match.getIpv4Match().getDestinationIp() != null) {
                            ofFlow.setDstIp(match.getIpv4Match().getDestinationIp());
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                            ofFlow.setName(ofFlow.getName() + "IP" + match.getIpv4Match().getDestinationIp());
                        } else if (match.getIpv4Match() != null && match.getIpv4Match().getDstDnsName() != null) {
                            ofFlow.setPriority(DYNAMIC_INTERNET_COMMUNICATION);
                        } else if (match.getIpv6Match() != null &&
                                match.getIpv6Match().getDestinationIp() != null) {
                            ofFlow.setDstIp(match.getIpv6Match().getDestinationIp());
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                            ofFlow.setName(ofFlow.getName() + "IP" + match.getIpv6Match().getDestinationIp());
                        } else if (match.getIpv6Match() != null &&
                                match.getIpv6Match().getDstDnsName() != null) {
                            ofFlow.setPriority(DYNAMIC_INTERNET_COMMUNICATION);
                        } else {
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                        }
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        if (FIXED_INTERNET_COMMUNICATION == ofFlow.getPriority()) {
                            toInternetStaticFlows.add(ofFlow);
                        } else {
                            toInternetDynamicFlows.add(ofFlow);
                        }
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
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);

                        if (match.getIpv4Match() != null &&
                                match.getIpv4Match().getProtocol() != 0) {
                            ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
                            ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        }

                        if (match.getIpv6Match() != null) {
                            ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
                            ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
                        }

                        if (ofFlow.getIpProto().equals(Constants.ICMP_PROTO)) {
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, ICMP, "All"));
                        }

                        if (!ofFlow.getEthType().equals(Constants.ETH_TYPE_IPV4) &&
                                !ofFlow.getEthType().equals(Constants.ETH_TYPE_IPV6)) {
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, ofFlow.getEthType(), "All"));

                        } else {
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, getProto(ofFlow.getIpProto()), "All"));
                        }

                        //tcp
                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getDestinationPortMatch() != null
                                && match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, TCP, match.getTcpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getSourcePortMatch() != null
                                && match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, TCP, match.getTcpMatch()
                                    .getSourcePortMatch().getPort()));
                        }
                        //udp
                        if (match.getUdpMatch() != null &&
                                match.getUdpMatch().getDestinationPortMatch() != null
                                && match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, UDP, match.getUdpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getUdpMatch() != null &&
                                match.getUdpMatch().getSourcePortMatch() != null
                                && match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, UDP, match.getUdpMatch()
                                    .getSourcePortMatch().getPort()));
                            if (ofFlow.getSrcPort().equals(Constants.DNS_PORT)) {
                                ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
                            }
                        }


                        if ((match.getIpv4Match() != null && match.getIpv4Match().getSourceIp() != null)) {
                            ofFlow.setSrcIp(match.getIpv4Match().getDestinationIp());
                            ofFlow.setName(ofFlow.getName() + "IP" + match.getIpv4Match().getSourceIp());
                        } else if (match.getIpv6Match() != null && match.getIpv6Match().getSourceIp() != null) {
                            ofFlow.setSrcIp(match.getIpv6Match().getSourceIp());
                            ofFlow.setName(ofFlow.getName() + "IP" + match.getIpv6Match().getSourceIp());
                        } else if (match.getIetfMudMatch().getController() != null &&
                                (match.getIetfMudMatch().getController().contains(MUD_URN))) {
                            ofFlow.setSrcIp(gatewayIp);
                            ofFlow.setName(ofFlow.getName() + "IP" + gatewayIp);
                            ofFlow.setPriority(FIXED_LOCAL_CONTROLLER_COMMUNICATION);
                        }
                        fromLocalStaticFlows.add(ofFlow);
                    } else {
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setSrcMac(switchMac);
                        ofFlow.setDstMac(deviceMac);
                        String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
                                .getEtherType();
                        ofFlow.setEthType(etherType);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        if (match.getIpv4Match() != null &&
                                match.getIpv4Match().getProtocol() != 0) {

                            ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                            ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
                        }

                        if (match.getIpv6Match() != null) {
                            ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
                            ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
                        }

                        if (ofFlow.getIpProto().equals(Constants.ICMP_PROTO)) {
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, ICMP, "All"));
                        }

                        if (!ofFlow.getEthType().equals(Constants.ETH_TYPE_IPV4) &&
                                !ofFlow.getEthType().equals(Constants.ETH_TYPE_IPV6)) {
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, ofFlow.getEthType(), "All"));

                        } else {
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, getProto(ofFlow.getIpProto()), "All"));

                        }

                        //tcp
                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getDestinationPortMatch() != null
                                && match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, TCP, match.getTcpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getSourcePortMatch() != null
                                && match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, TCP, match.getTcpMatch()
                                    .getSourcePortMatch().getPort()));
                        }
                        //udp
                        if (match.getUdpMatch() != null &&
                                match.getUdpMatch().getDestinationPortMatch() != null
                                && match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                            ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, UDP, match.getUdpMatch()
                                    .getDestinationPortMatch().getPort()));
                        }

                        if (match.getUdpMatch() != null &&
                                match.getUdpMatch().getSourcePortMatch() != null
                                && match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                            ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
                            ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, UDP, match.getUdpMatch()
                                    .getSourcePortMatch().getPort()));
                            if (ofFlow.getSrcPort().equals(Constants.DNS_PORT)) {
                                ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
                            }
                        }

                        if (match.getIpv4Match() != null && match.getIpv4Match().getSourceIp() != null) {
                            ofFlow.setSrcIp(match.getIpv4Match().getSourceIp());
                            ofFlow.setName(ofFlow.getName() + "IP" + match.getIpv4Match().getSourceIp());
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                        } else if (match.getIpv4Match() != null && match.getIpv4Match().getSrcDnsName() != null) {
                            ofFlow.setPriority(DYNAMIC_INTERNET_COMMUNICATION);
                        } else if (match.getIpv6Match() != null && match.getIpv6Match().getSourceIp() != null) {
                            ofFlow.setSrcIp(match.getIpv6Match().getSourceIp());
                            ofFlow.setName(ofFlow.getName() + "IP" + match.getIpv6Match().getSourceIp());
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                        } else if (match.getIpv6Match() != null && match.getIpv6Match().getSrcDnsName() != null) {
                            ofFlow.setPriority(DYNAMIC_INTERNET_COMMUNICATION);
                        } else {
                            ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
                        }

                        if (DYNAMIC_INTERNET_COMMUNICATION == ofFlow.getPriority()) {
                            fromInternetDynamicFlows.add(ofFlow);
                        } else {
                            fromInternetStaticFlows.add(ofFlow);
                        }
                    }
                }
            }
        }

        DeviceMUDFlowMap deviceFlowMap = new DeviceMUDFlowMap();
        deviceFlowMap.setFromInternetDynamicFlows(fromInternetDynamicFlows);
        deviceFlowMap.setFromInternetStaticFlows(fromInternetStaticFlows);
        deviceFlowMap.setToInternetDynamicFlows(toInternetDynamicFlows);
        deviceFlowMap.setToInternetStaticFlows(toInternetStaticFlows);
        deviceFlowMap.setToLocalStaticFlows(toLocalStaticFlows);
        deviceFlowMap.setFromLocalStaticFlows(fromLocalStaticFlows);
        return deviceFlowMap;

    }

    private String getProto(String num) {
        if (Constants.TCP_PROTO.equals(num)) {
            return TCP;
        } else if (Constants.UDP_PROTO.equals(num)) {
            return UDP;
        } else if (Constants.ICMP_PROTO.equals(num)) {
            return ICMP;
        }
        return num;
    }

    private void installLocalNetworkRules(String deviceMac, DeviceMUDFlowMap deviceMUDFlowMap) {
        OFFlow ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_ARP);
        ofFlow.setName(String.format(TO_LOCAL_FEATURE_NAME, ARP,"All"));
        ofFlow.setPriority(FIXED_LOCAL_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getToLocalStaticFlows().add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_ARP);
        ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, ARP,"All"));
        ofFlow.setPriority(FIXED_LOCAL_COMMUNICATION);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);

//        ofFlow = new OFFlow();
//        ofFlow.setDstMac(deviceMac);
//        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//        ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, ICMP,"All"));
//        ofFlow.setIpProto(Constants.ICMP_PROTO);
//        ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
//        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);
//
//        ofFlow = new OFFlow();
//        ofFlow.setDstMac(deviceMac);
//        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//        ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, TCP,"All"));
//        ofFlow.setIpProto(Constants.TCP_PROTO);
//        ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
//        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);
//
//        ofFlow = new OFFlow();
//        ofFlow.setDstMac(deviceMac);
//        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//        ofFlow.setName(String.format(FROM_LOCAL_FEATURE_NAME, UDP,"All"));
//        ofFlow.setIpProto(Constants.UDP_PROTO);
//        ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
//        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//        deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);
    }

    private void installInternetNetworkRules(String deviceMac, String switchMac, DeviceMUDFlowMap deviceMUDFlowMap) {

//        OFFlow ofFlow = new OFFlow();
//        ofFlow.setSrcMac(switchMac);
//        ofFlow.setDstMac(deviceMac);
//        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//        ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, TCP,"All"));
//        ofFlow.setIpProto(Constants.TCP_PROTO);
//        ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
//        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//        deviceMUDFlowMap.getFromInternetStaticFlows().add(ofFlow);
//
//        ofFlow = new OFFlow();
//        ofFlow.setSrcMac(switchMac);
//        ofFlow.setDstMac(deviceMac);
//        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//        ofFlow.setIpProto(Constants.UDP_PROTO);
//        ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, UDP,"All"));
//        ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
//        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//        deviceMUDFlowMap.getFromInternetStaticFlows().add(ofFlow);
//
//        ofFlow = new OFFlow();
//        ofFlow.setSrcMac(deviceMac);
//        ofFlow.setDstMac(switchMac);
//        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//        ofFlow.setIpProto(Constants.ICMP_PROTO);
//        ofFlow.setName(String.format(FROM_INTERNET_FEATURE_NAME, ICMP,"All"));
//        ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
//        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//        deviceMUDFlowMap.getToInternetStaticFlows().add(ofFlow);
//
//        ofFlow = new OFFlow();
//        ofFlow.setSrcMac(deviceMac);
//        ofFlow.setDstMac(switchMac);
//        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//        ofFlow.setIpProto(Constants.UDP_PROTO);
//        ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, UDP,"All"));
//        ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
//        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//        deviceMUDFlowMap.getToInternetStaticFlows().add(ofFlow);
//
//        ofFlow = new OFFlow();
//        ofFlow.setSrcMac(deviceMac);
//        ofFlow.setDstMac(switchMac);
//        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//        ofFlow.setIpProto(Constants.TCP_PROTO);
//        ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, TCP,"All"));
//        ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
//        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//        deviceMUDFlowMap.getToInternetStaticFlows().add(ofFlow);
//
//        ofFlow = new OFFlow();
//        ofFlow.setSrcMac(switchMac);
//        ofFlow.setDstMac(deviceMac);
//        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//        ofFlow.setIpProto(Constants.ICMP_PROTO);
//        ofFlow.setName(String.format(TO_INTERNET_FEATURE_NAME, ICMP,"All"));
//        ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
//        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
//        deviceMUDFlowMap.getFromInternetStaticFlows().add(ofFlow);

    }

    private OFFlow getMatchingFlow(OFFlow currentFlow, Map<Integer, OFFlow> ofFlows) {
        for (int key : ofFlows.keySet()) {
            OFFlow flow = ofFlows.get(key);
            String srcMac = currentFlow.getSrcMac();
            String dstMac = currentFlow.getDstMac();
            String ethType = currentFlow.getEthType();
            String vlanId = "*";
            String srcIp = currentFlow.getSrcIp() == null ? "*" : currentFlow.getSrcIp();
            String dstIp = currentFlow.getDstIp() == null ? "*" : currentFlow.getDstIp();
            String ipProto = currentFlow.getIpProto() == null ? "*" : currentFlow.getIpProto();
            String srcPort = currentFlow.getSrcPort() == null ? "*" : currentFlow.getSrcPort();
            String dstPort = currentFlow.getDstPort() == null ? "*" : currentFlow.getDstPort();

            //TODO temporary for testing purposes
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

            if (flow.getDstIp().contains("/")) {
                String ip = flow.getDstIp().split("/")[0];
                if (flow.getDstIp().equals(Constants.LINK_LOCAL_MULTICAST_IP_RANGE)) {
                    ip = "ff";
                }
                ipMatching = ipMatching && dstIp.startsWith(flow.getDstIp().split("/")[0]) || flow.getDstIp().equals("*");
            } else {
                ipMatching = ipMatching && (dstIp.equals(flow.getDstIp())  || flow.getDstIp().equals("*"));
            }

            boolean condition = (srcMac.equals(flow.getSrcMac()) || flow.getSrcMac().equals("*"))&&
                    (dstMac.equals(flow.getDstMac())  || flow.getDstMac().equals("*"))&&
                    (ethType.equals(flow.getEthType()) || flow.getEthType().equals("*")) &&
                    (vlanId.equals(flow.getVlanId())  || flow.getVlanId().equals("*"))&&
                    ipMatching &&
                    (ipProto.equals(flow.getIpProto())  || flow.getIpProto().equals("*"))&&
                    (srcPort.equals(flow.getSrcPort())  || flow.getSrcPort().equals("*"))&&
                    (dstPort.equals(flow.getDstPort()) || flow.getDstPort().equals("*"));

            if (condition) {
                return flow;
            }
        }
        return null;
    }



}
