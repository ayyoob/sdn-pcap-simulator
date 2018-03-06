package com.ayyoob.sdn.of.simulator.apps;

import com.ayyoob.sdn.of.simulator.*;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.*;
import java.nio.file.Paths;
import java.util.*;

public class IoTDeviceFlowBuilderWithRate implements ControllerApp {

    private static final int COMMON_FLOW_PRIORITY = 1000;
    private static final int D2G_FIXED_FLOW_PRIORITY = 850;
    private static final int D2G_DYNAMIC_FLOW_PRIORITY = 810;
    private static final int D2G_PRIORITY = 800;
    private static final int G2D_FIXED_FLOW_PRIORITY = 750;
    private static final int G2D_DYNAMIC_FLOW_PRIORITY = 710;
    private static final int G2D_PRIORITY = 700;
    private static final int L2D_FIXED_FLOW_PRIORITY = 650;
    private static final int L2D_DYNAMIC_FLOW_PRIORITY = 610;
    private static final int L2D_PRIORITY = 600;
    private static final int SKIP_FLOW_PRIORITY = 400;
    private static final int SKIP_FLOW_HIGHER_PRIORITY = 950;
    private static String ignoreMacPrefix[] = {"01:00:5E", "33:33", "FF:FF:FF"};

    private static final long MAX_FLOWS_PER_DEVICE = 500;
    private static final double MIN_FLOW_IMPACT_THRESHOLD = 2; //percentage
    private static final long MIN_TIME_FOR_FLOWS_MILLI_SECONDS = 120000;

    private static boolean enabled = true;
    private static List<String> devices = new ArrayList<String>();
    private static boolean logger = false;
    private static boolean initMem =false;
    private static boolean initPerf =false;

    public void init(JSONObject jsonObject) {
        enabled = (Boolean) jsonObject.get("isIoTDeviceFlowBuilderEnable");
        if (!enabled) {
            return;
        }
        JSONArray devs = (JSONArray) jsonObject.get("devices");
        Iterator<String> iterator = devs.iterator();
        while (iterator.hasNext()) {
            String deviceMacName = iterator.next().toLowerCase();
            devices.add(deviceMacName);
        }
    }

    public void process(String dpId, SimPacket packet) {
        if (!enabled) {
            return;
        }
        if (isIgnored(packet.getSrcMac()) || isIgnored(packet.getDstMac())) {
            return;
        }
        logPerformance(dpId,1);
        String srcMac = packet.getSrcMac();
        String destMac = packet.getDstMac();
        OFSwitch ofSwitch = OFController.getInstance().getSwitch(dpId);
        if (!srcMac.equals(ofSwitch.getMacAddress())) {
            synchronized (ofSwitch) {
                if (getActiveFlows(dpId, srcMac).size() < 10) {
                    initializeDeviceFlows(dpId, srcMac, ofSwitch.getMacAddress());
                }
            }
        }

        if (!destMac.equals(ofSwitch.getMacAddress())) {
            synchronized (ofSwitch) {
                if (getActiveFlows(dpId, destMac).size() < 10) {
                    initializeDeviceFlows(dpId, destMac, ofSwitch.getMacAddress());
                } else {

                }
            }
        }

        if (srcMac.equals(ofSwitch.getMacAddress()) && packet.getIpProto()!=null
                && packet.getIpProto().equals(Constants.UDP_PROTO)
                && packet.getSrcPort().equals(Constants.DNS_PORT)) {
            //ignore.
        } else {

            String dstIp = packet.getDstIp();
            String srcIp = packet.getSrcIp();
            String protocol = packet.getIpProto();
            String srcPort = packet.getSrcPort();
            String dstPort = packet.getDstPort();

            //Only UDP and TCP proto
            if (protocol != null && (protocol.equals(Constants.TCP_PROTO) || protocol.equals(Constants.UDP_PROTO))) {
                // Device 2 Gateway flow
                if (destMac.equals(ofSwitch.getMacAddress()) && Integer.parseInt(dstPort) != 53
                        && Integer.parseInt(dstPort) != 123) {
                    String deviceMac = srcMac;

                    if (protocol.equals(Constants.TCP_PROTO) && packet.getTcpFlag() == SimPacket.Flag.SYN) {
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setSrcMac(deviceMac);
                        ofFlow.setDstMac(ofSwitch.getMacAddress());
                        ofFlow.setDstPort(dstPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(D2G_FIXED_FLOW_PRIORITY);

                        List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac, D2G_DYNAMIC_FLOW_PRIORITY);
                        for (OFFlow flow : deviceFlows) {
                            if (flow.getIpProto().equals(protocol) && flow.getDstPort().equals(dstPort)) {
                                removeFlow(dpId, flow, deviceMac);
                            }
                        }

                        OFController.getInstance().addFlow(dpId, ofFlow);


                        ofFlow = new OFFlow();
                        ofFlow.setSrcMac(ofSwitch.getMacAddress());
                        ofFlow.setDstMac(deviceMac);
                        ofFlow.setSrcPort(dstPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(G2D_FIXED_FLOW_PRIORITY);

                        deviceFlows = getActiveFlows(dpId, deviceMac, G2D_DYNAMIC_FLOW_PRIORITY);
                        for (OFFlow flow : deviceFlows) {
                            if (flow.getIpProto().equals(protocol) && flow.getSrcPort().equals(dstPort)) {
                                removeFlow(dpId, flow, deviceMac);
                            }
                        }

                        OFController.getInstance().addFlow(dpId, ofFlow);
                    } else if (protocol.equals(Constants.TCP_PROTO) && packet.getTcpFlag() == SimPacket.Flag.SYN_ACK) {
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setSrcMac(deviceMac);
                        ofFlow.setDstMac(ofSwitch.getMacAddress());
                        ofFlow.setSrcPort(srcPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(D2G_FIXED_FLOW_PRIORITY);
                        List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac, D2G_DYNAMIC_FLOW_PRIORITY);
                        for (OFFlow flow : deviceFlows) {
                            if (flow.getIpProto().equals(protocol) && flow.getSrcPort().equals(srcPort)) {
                                removeFlow(dpId, flow, deviceMac);
                            }
                        }
                        OFController.getInstance().addFlow(dpId, ofFlow);


                        ofFlow = new OFFlow();
                        ofFlow.setSrcMac(ofSwitch.getMacAddress());
                        ofFlow.setDstMac(deviceMac);
                        ofFlow.setDstPort(srcPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(G2D_FIXED_FLOW_PRIORITY);
                        deviceFlows = getActiveFlows(dpId, deviceMac, G2D_DYNAMIC_FLOW_PRIORITY);
                        for (OFFlow flow : deviceFlows) {
                            if (flow.getIpProto().equals(protocol) && flow.getDstPort().equals(srcPort)) {
                                removeFlow(dpId, flow, deviceMac);
                            }
                        }
                        OFController.getInstance().addFlow(dpId, ofFlow);
                    } else {
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setSrcMac(deviceMac);
                        ofFlow.setDstMac(ofSwitch.getMacAddress());
                        ofFlow.setDstPort(dstPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
                        addFlow(dpId, ofFlow, deviceMac);
                    }
                    // Gateway to Device
                } else if (srcMac.equals(ofSwitch.getMacAddress()) && Integer.parseInt(srcPort) != 53
                        && Integer.parseInt(srcPort) != 123) {
                    String deviceMac = destMac;
                    if (protocol.equals(Constants.TCP_PROTO) && packet.getTcpFlag() == SimPacket.Flag.SYN) {
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setSrcMac(ofSwitch.getMacAddress());
                        ofFlow.setDstMac(deviceMac);
                        ofFlow.setDstPort(dstPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(G2D_FIXED_FLOW_PRIORITY);

                        List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac, G2D_DYNAMIC_FLOW_PRIORITY);
                        for (OFFlow flow : deviceFlows) {
                            if (flow.getIpProto().equals(protocol) && flow.getDstPort().equals(dstPort)) {
                                removeFlow(dpId, flow, deviceMac);
                            }
                        }

                        OFController.getInstance().addFlow(dpId, ofFlow);


                        ofFlow = new OFFlow();
                        ofFlow.setSrcMac(deviceMac);
                        ofFlow.setDstMac(ofSwitch.getMacAddress());
                        ofFlow.setSrcPort(dstPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(D2G_FIXED_FLOW_PRIORITY);
                        deviceFlows = getActiveFlows(dpId, deviceMac, D2G_DYNAMIC_FLOW_PRIORITY);
                        for (OFFlow flow : deviceFlows) {
                            if (flow.getIpProto().equals(protocol) && flow.getSrcPort().equals(dstPort)) {
                                removeFlow(dpId, flow, deviceMac);
                            }
                        }
                        OFController.getInstance().addFlow(dpId, ofFlow);
                    } else if (protocol.equals(Constants.TCP_PROTO) && packet.getTcpFlag() == SimPacket.Flag.SYN_ACK) {
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setSrcMac(ofSwitch.getMacAddress());
                        ofFlow.setDstMac(deviceMac);
                        ofFlow.setSrcPort(srcPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(G2D_FIXED_FLOW_PRIORITY);
                        List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac, G2D_DYNAMIC_FLOW_PRIORITY);
                        for (OFFlow flow : deviceFlows) {
                            if (flow.getIpProto().equals(protocol) && flow.getSrcPort().equals(srcPort)) {
                                removeFlow(dpId, flow, deviceMac);
                            }
                        }
                        OFController.getInstance().addFlow(dpId, ofFlow);


                        ofFlow = new OFFlow();
                        ofFlow.setSrcMac(deviceMac);
                        ofFlow.setDstMac(ofSwitch.getMacAddress());
                        ofFlow.setDstPort(srcPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(D2G_FIXED_FLOW_PRIORITY);
                        deviceFlows = getActiveFlows(dpId, deviceMac, D2G_DYNAMIC_FLOW_PRIORITY);
                        for (OFFlow flow : deviceFlows) {
                            if (flow.getIpProto().equals(protocol) && flow.getDstPort().equals(srcPort)) {
                                removeFlow(dpId, flow, deviceMac);
                            }
                        }
                        OFController.getInstance().addFlow(dpId, ofFlow);
                    } else {
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setSrcMac(ofSwitch.getMacAddress());
                        ofFlow.setDstMac(deviceMac);
                        ofFlow.setDstPort(dstPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setPriority(G2D_DYNAMIC_FLOW_PRIORITY);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        addFlow(dpId, ofFlow, deviceMac);
                    }
                    //
                } else if ((!destMac.equals(ofSwitch.getMacAddress())) && !isIgnored(destMac)) {

                    if (protocol.equals(Constants.TCP_PROTO) && packet.getTcpFlag() == SimPacket.Flag.SYN) {
                        String deviceMac = destMac;
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setDstMac(deviceMac);
                        ofFlow.setDstPort(dstPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(L2D_FIXED_FLOW_PRIORITY);

                        List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac, L2D_DYNAMIC_FLOW_PRIORITY);
                        for (OFFlow flow : deviceFlows) {
                            if (flow.getIpProto().equals(protocol) && flow.getDstPort().equals(dstPort)) {
                                removeFlow(dpId, flow, deviceMac);
                            }
                        }

                        OFController.getInstance().addFlow(dpId, ofFlow);


                        ofFlow = new OFFlow();
                        ofFlow.setSrcMac(deviceMac);
                        ofFlow.setSrcPort(dstPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(L2D_FIXED_FLOW_PRIORITY);
                        OFController.getInstance().addFlow(dpId, ofFlow);
                    } else if (protocol.equals(Constants.TCP_PROTO) && packet.getTcpFlag() == SimPacket.Flag.SYN_ACK) {
                        String deviceMac = srcMac;

                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setDstMac(deviceMac);
                        ofFlow.setDstPort(srcPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(L2D_FIXED_FLOW_PRIORITY);

                        List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac, L2D_DYNAMIC_FLOW_PRIORITY);
                        for (OFFlow flow : deviceFlows) {
                            if (flow.getIpProto().equals(protocol) && flow.getDstPort().equals(srcPort)) {
                                removeFlow(dpId, flow, deviceMac);
                            }
                        }
                        OFController.getInstance().addFlow(dpId, ofFlow);


                        ofFlow = new OFFlow();
                        ofFlow.setSrcMac(deviceMac);
                        ofFlow.setSrcPort(srcPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        ofFlow.setPriority(L2D_FIXED_FLOW_PRIORITY);
                        OFController.getInstance().addFlow(dpId, ofFlow);

                    } else {
                        String deviceMac = destMac;
                        OFFlow ofFlow = new OFFlow();
                        ofFlow.setDstMac(deviceMac);
                        ofFlow.setDstPort(dstPort);
                        ofFlow.setIpProto(protocol);
                        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                        ofFlow.setPriority(L2D_DYNAMIC_FLOW_PRIORITY);
                        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                        addFlow(dpId, ofFlow, deviceMac);
                    }
                }
            }
        }
    }

    private void addFlow(String dpId, OFFlow ofFlow, String deviceMac) {
        List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac, ofFlow.getPriority());
        if (deviceFlows.size() < MAX_FLOWS_PER_DEVICE) {
            ofFlow.setCreatedTimestamp(OFController.getInstance().getSwitch(dpId).getCurrentTime());
            OFController.getInstance().addFlow(dpId, ofFlow);
        } else {
            OFFlow tobeRemoved = null;
            double packetCountRateForPriorityLevel = getTotalPacketCountRate(dpId, deviceMac, ofFlow.getPriority());
            int flowsConsideredForRemoval = 0;
            for (OFFlow flow : deviceFlows) {

                long currentTime = OFController.getInstance().getSwitch(dpId).getCurrentTime();
                long flowInitializedTime = flow.getCreatedTimestamp();
                long age = currentTime - flowInitializedTime;
                if (currentTime - flowInitializedTime > MIN_TIME_FOR_FLOWS_MILLI_SECONDS) {
                    if (tobeRemoved == null) {
                        Double flowImpact = ((flow.getPacketCount() * 1.0)/age) / packetCountRateForPriorityLevel;
                        if (MIN_FLOW_IMPACT_THRESHOLD > (flowImpact * 100)) {
                            tobeRemoved = flow;
                            flowsConsideredForRemoval++;
                        }
                    } else {
                        flowsConsideredForRemoval++;
                        Double flowImpact = ((flow.getPacketCount() * 1.0)/age) / packetCountRateForPriorityLevel;
                        Double tobeRemovedFlowImpact = ((tobeRemoved.getPacketCount() * 1.0)/age) / packetCountRateForPriorityLevel;
                        if (tobeRemovedFlowImpact > flowImpact) {
                            tobeRemoved = flow;
                        }
                    }
                }
            }
            if (tobeRemoved != null && flowsConsideredForRemoval >= 1) {
                removeFlow(dpId, tobeRemoved, deviceMac);
                OFController.getInstance().addFlow(dpId, ofFlow);
            }

        }
    }

    private void removeFlow(String dpId, OFFlow ofFlow, String deviceMac) {

//        deviceFlowTimeMap.remove(ofFlow);
//
//        long count[] = deviceFlowPacketCountBeenRemoved.get(deviceMac);
//        if (ofFlow.getPriority() == D2G_DYNAMIC_FLOW_PRIORITY) {
//            count[0] = count[0] + ofFlow.getPacketCount();
//        } else if (ofFlow.getPriority() == G2D_DYNAMIC_FLOW_PRIORITY) {
//            count[1] = count[1] + ofFlow.getPacketCount();
//        } else if (ofFlow.getPriority() == L2D_DYNAMIC_FLOW_PRIORITY) {
//            count[2] = count[2] + ofFlow.getPacketCount();
//        }
//        deviceFlowPacketCountBeenRemoved.put(deviceMac, count);
        OFController.getInstance().removeFlow(dpId, ofFlow);
    }


    public List<OFFlow> getActiveFlows(String dpId, String deviceMac) {
        List<OFFlow> flowList = OFController.getInstance().getAllFlows(dpId);
        List<OFFlow> deviceFlowList = new ArrayList<OFFlow>();
        for (OFFlow ofFlow : flowList) {
            if (ofFlow.getSrcMac().equals(deviceMac) || ofFlow.getDstMac().equals(deviceMac)) {
                deviceFlowList.add(ofFlow);
            }
        }
        return deviceFlowList;
    }

    public List<OFFlow> getActiveFlows(String dpId, String deviceMac, int priority) {
        List<OFFlow> flowList = OFController.getInstance().getAllFlows(dpId);
        List<OFFlow> deviceFlowList = new ArrayList<OFFlow>();
        for (OFFlow ofFlow : flowList) {
            if (ofFlow.getSrcMac().equals(deviceMac) || ofFlow.getDstMac().equals(deviceMac)) {
                if (ofFlow.getPriority() == priority) {
                    deviceFlowList.add(ofFlow);
                }
            }
        }
        return deviceFlowList;
    }

    public List<OFFlow> getActiveFlowsForPriorities(String dpId, String deviceMac, List<Integer> priority) {
        List<OFFlow> flowList = OFController.getInstance().getAllFlows(dpId);
        List<OFFlow> deviceFlowList = new ArrayList<OFFlow>();
        for (OFFlow ofFlow : flowList) {
            if (ofFlow.getSrcMac().equals(deviceMac) || ofFlow.getDstMac().equals(deviceMac)) {
                if (priority.contains(ofFlow.getPriority())) {
                    deviceFlowList.add(ofFlow);
                }
            }
        }
        return deviceFlowList;
    }

//    public long getTotalPacketCount(String dpId, String deviceMac, int priority) {
//        long totalPacketCount = 0;
//
//        List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac);
//        for (OFFlow ofFlow : deviceFlows) {
//            if (ofFlow.getPriority() == priority || ofFlow.getPriority() == (priority - 10) || ofFlow.getPriority() == (priority + 40)) {
//                totalPacketCount = totalPacketCount + ofFlow.getPacketCount();
//            }
//        }
//
//        return totalPacketCount;
//    }
    public double getTotalPacketCountRate(String dpId, String deviceMac, int priority) {
        double totalPacketCount = 0;

        List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac);
        for (OFFlow ofFlow : deviceFlows) {
            if (ofFlow.getPriority() == priority || ofFlow.getPriority() == (priority - 10) || ofFlow.getPriority() == (priority + 40)) {
                totalPacketCount = totalPacketCount +( (ofFlow.getPacketCount()*1.0)/
                        (OFController.getInstance().getSwitch(dpId).getCurrentTime()- ofFlow.getCreatedTimestamp()));
            }
        }

        return totalPacketCount;
    }

    private boolean isIgnored(String mac) {
        for (String prefix : ignoreMacPrefix) {
            if (mac.contains(prefix.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    public void initializeDeviceFlows(String dpId, String deviceMac, String gwMac) {
        if (isIgnored(deviceMac)) {
            return;
        }
        //SKIP GATEWAY
        OFFlow ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac(gwMac);
        ofFlow.setDstIp(OFController.getInstance().getSwitch(dpId).getIp());
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(SKIP_FLOW_HIGHER_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setSrcMac(gwMac);
        ofFlow.setSrcIp(OFController.getInstance().getSwitch(dpId).getIp());
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(SKIP_FLOW_HIGHER_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        //DNS
        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_ARP);
        ofFlow.setPriority(COMMON_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_ARP);
        ofFlow.setPriority(COMMON_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac(gwMac);
        ofFlow.setIpProto(Constants.UDP_PROTO);
        ofFlow.setDstPort(Constants.DNS_PORT);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(COMMON_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(gwMac);
        ofFlow.setDstMac(deviceMac);
        ofFlow.setIpProto(Constants.UDP_PROTO);
        ofFlow.setSrcPort(Constants.DNS_PORT);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(COMMON_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        //NTP
        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac(gwMac);
        ofFlow.setIpProto(Constants.UDP_PROTO);
        ofFlow.setDstPort(Constants.NTP_PORT);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(COMMON_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(gwMac);
        ofFlow.setDstMac(deviceMac);
        ofFlow.setIpProto(Constants.UDP_PROTO);
        ofFlow.setSrcPort(Constants.NTP_PORT);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(COMMON_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        //ICMP
        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac(gwMac);
        ofFlow.setIpProto(Constants.ICMP_PROTO);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(COMMON_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(gwMac);
        ofFlow.setDstMac(deviceMac);
        ofFlow.setIpProto(Constants.ICMP_PROTO);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(COMMON_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        //Device -> GW
        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac(gwMac);
        ofFlow.setIpProto(Constants.TCP_PROTO);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(D2G_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac(gwMac);
        ofFlow.setIpProto(Constants.UDP_PROTO);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(D2G_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        OFController.getInstance().addFlow(dpId, ofFlow);

        //GW - > Device

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(gwMac);
        ofFlow.setDstMac(deviceMac);
        ofFlow.setIpProto(Constants.TCP_PROTO);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(G2D_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(gwMac);
        ofFlow.setDstMac(deviceMac);
        ofFlow.setIpProto(Constants.UDP_PROTO);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(G2D_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        OFController.getInstance().addFlow(dpId, ofFlow);

        //Local
        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(L2D_PRIORITY);
        ofFlow.setIpProto(Constants.TCP_PROTO);
        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(L2D_PRIORITY);
        ofFlow.setIpProto(Constants.UDP_PROTO);
        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setIpProto(Constants.ICMP_PROTO);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(L2D_PRIORITY + 1);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setPriority(SKIP_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setPriority(SKIP_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        long flowCount[] = {0, 0, 0};
    }

    public void complete() {
        if (!enabled) {
            return;
        }
        Set<String> switchMap = OFController.getInstance().getSwitchIds();
        for (String dpId : switchMap) {
            List<OFFlow> flowsTobeRemoved = new ArrayList<OFFlow>();
            List<OFFlow> flowsTobeAdded = new ArrayList<>();
            for (String deviceMac : devices) {
                double totalPacketCountRate = getTotalPacketCountRate(dpId, deviceMac, D2G_DYNAMIC_FLOW_PRIORITY);
                List<Integer> priorities = new ArrayList<>();
                priorities.add(D2G_DYNAMIC_FLOW_PRIORITY);
                //priorities.add(D2G_FIXED_FLOW_PRIORITY);
                List<OFFlow> ofFlows = getActiveFlowsForPriorities(dpId, deviceMac, priorities);
                long currentTime = OFController.getInstance().getSwitch(dpId).getCurrentTime();
                for (OFFlow ofFlow : ofFlows) {
                    long flowInitializedTime = ofFlow.getCreatedTimestamp();
                    long age = currentTime - flowInitializedTime;
                    Double flowImpact = ((ofFlow.getPacketCount() * 1.0)/age) / totalPacketCountRate;
                    if ((flowImpact * 100) < MIN_FLOW_IMPACT_THRESHOLD) {
                        flowsTobeRemoved.add(ofFlow);
                        if (ofFlow.getPriority() == D2G_FIXED_FLOW_PRIORITY) {
                            OFFlow reverseFlow = ofFlow.copy();
                            reverseFlow.setSrcMac(ofFlow.getDstMac());
                            reverseFlow.setDstMac(ofFlow.getSrcMac());
                            reverseFlow.setSrcPort(ofFlow.getDstPort());
                            reverseFlow.setDstPort(ofFlow.getSrcPort());
                            flowsTobeRemoved.add(reverseFlow);
                        }
                    } else {

                        OFFlow reverseFlow = ofFlow.copy();
                        reverseFlow.setSrcMac(ofFlow.getDstMac());
                        reverseFlow.setDstMac(ofFlow.getSrcMac());
                        reverseFlow.setSrcPort(ofFlow.getDstPort());
                        reverseFlow.setDstPort(ofFlow.getSrcPort());
                        flowsTobeAdded.add(reverseFlow);
                    }
                }


                totalPacketCountRate = getTotalPacketCountRate(dpId, deviceMac, G2D_DYNAMIC_FLOW_PRIORITY);
                priorities = new ArrayList<>();
                priorities.add(G2D_DYNAMIC_FLOW_PRIORITY);
                //priorities.add(G2D_FIXED_FLOW_PRIORITY);
                ofFlows = getActiveFlowsForPriorities(dpId, deviceMac, priorities);
                for (OFFlow ofFlow : ofFlows) {
                    long flowInitializedTime = ofFlow.getCreatedTimestamp();
                    long age = currentTime - flowInitializedTime;
                    Double flowImpact = ((ofFlow.getPacketCount() * 1.0)/age) / totalPacketCountRate;
                    if ((flowImpact * 100) < MIN_FLOW_IMPACT_THRESHOLD) {
                        flowsTobeRemoved.add(ofFlow);
                        if (ofFlow.getPriority() == G2D_FIXED_FLOW_PRIORITY) {
                            OFFlow reverseFlow = ofFlow.copy();
                            reverseFlow.setSrcMac(ofFlow.getDstMac());
                            reverseFlow.setDstMac(ofFlow.getSrcMac());
                            reverseFlow.setSrcPort(ofFlow.getDstPort());
                            reverseFlow.setDstPort(ofFlow.getSrcPort());
                            flowsTobeRemoved.add(reverseFlow);
                        }
                    } else {
                        OFFlow reverseFlow = ofFlow.copy();
                        reverseFlow.setSrcMac(ofFlow.getDstMac());
                        reverseFlow.setDstMac(ofFlow.getSrcMac());
                        reverseFlow.setSrcPort(ofFlow.getDstPort());
                        reverseFlow.setDstPort(ofFlow.getSrcPort());
                        flowsTobeAdded.add(reverseFlow);
                    }
                }

                totalPacketCountRate = getTotalPacketCountRate(dpId, deviceMac, L2D_DYNAMIC_FLOW_PRIORITY);
                priorities = new ArrayList<>();
                priorities.add(L2D_DYNAMIC_FLOW_PRIORITY);
                //priorities.add(L2D_FIXED_FLOW_PRIORITY);
                ofFlows = getActiveFlowsForPriorities(dpId, deviceMac, priorities);
                for (OFFlow ofFlow : ofFlows) {
                    long flowInitializedTime = ofFlow.getCreatedTimestamp();
                    long age = currentTime - flowInitializedTime;
                    Double flowImpact = ((ofFlow.getPacketCount() * 1.0)/age) / totalPacketCountRate;
                    if ((flowImpact * 100) < MIN_FLOW_IMPACT_THRESHOLD) {
                        flowsTobeRemoved.add(ofFlow);
                        if (ofFlow.getPriority() == L2D_FIXED_FLOW_PRIORITY) {
                            OFFlow reverseFlow = ofFlow.copy();
                            reverseFlow.setSrcMac(ofFlow.getDstMac());
                            reverseFlow.setDstMac(ofFlow.getSrcMac());
                            reverseFlow.setSrcPort(ofFlow.getDstPort());
                            reverseFlow.setDstPort(ofFlow.getSrcPort());
                            flowsTobeRemoved.add(reverseFlow);
                        }
                    } else {
                        OFFlow reverseFlow = ofFlow.copy();
                        reverseFlow.setDstMac(ofFlow.getSrcMac());
                        reverseFlow.setSrcMac(ofFlow.getDstMac());
                        reverseFlow.setSrcPort(ofFlow.getDstPort());
                        reverseFlow.setDstPort(ofFlow.getSrcPort());
                        flowsTobeAdded.add(reverseFlow);
                    }
                }
                for (OFFlow ofFlow : flowsTobeRemoved) {
                    removeFlow(dpId, ofFlow, deviceMac);
                }
                for (OFFlow ofFlow : flowsTobeAdded) {
                    OFController.getInstance().addFlow(dpId, ofFlow);
                }
                String currentPath = Paths.get(".").toAbsolutePath().normalize().toString();

                File workingDirectory = new File(currentPath + File.separator + "result");
                if (!workingDirectory.exists()) {
                    workingDirectory.mkdir();
                }

//                File deviceFile = new File(currentPath + File.pathSeparator
//                        + "result" + File.pathSeparator + deviceMac + ".txt");
                PrintWriter writer = null;
                try {
                    writer = new PrintWriter(currentPath + File.separator
                            + "result" + File.separator + deviceMac + "_flows.csv", "UTF-8");
                    ofFlows = getActiveFlows(dpId, deviceMac);
                    if (ofFlows.size() > 0) {
                        System.out.println("Device : " + deviceMac);
                        boolean first = true;
                        for (OFFlow ofFlow : ofFlows) {
                            if (ofFlow.getPriority() == SKIP_FLOW_HIGHER_PRIORITY || ofFlow.getPriority() == SKIP_FLOW_PRIORITY ) {
                                continue;
                            }
                            if (first) {
                                System.out.println(ofFlow.getFlowHeaderString());
                                writer.println(ofFlow.getFlowHeaderWithoutFlowStat());
                                first = false;
                            }
                            System.out.println(ofFlow.getFlowString());
                            writer.println(ofFlow.getFlowStringWithoutFlowStat());
                        }
                    }
                } catch (FileNotFoundException | UnsupportedEncodingException e) {
                    e.printStackTrace();
                } finally {
                    if (writer != null) {
                        writer.close();
                    }
                }


            }
            logPerformance(dpId, 0);
        }


    }

    private static void logPerformance(String dpId, int count) {
        if(!logger) {
            return;
        }
        try{
            String currentPath = Paths.get(".").toAbsolutePath().normalize().toString();

            File workingDirectory = new File(currentPath + File.separator + "result");
            if (!workingDirectory.exists()) {
                workingDirectory.mkdir();
            }
            String loggerFilePath = currentPath + File.separator + "result";
            File file = new File(loggerFilePath + File.separator + dpId + "_"+ "performanceoutput.csv");
            if (!file.exists()) {
                file.createNewFile();
            }
            FileWriter writer = new FileWriter(file, true);
            if (!initPerf) {
                writer.write( "timestamp,stat\n");
                initPerf = true;
            }
            String record = OFController.getInstance().getSwitch(dpId).getCurrentTime()-1 + "," + 0;
            writer.write(record + "\n");
            record = OFController.getInstance().getSwitch(dpId).getCurrentTime() + "," + count;
            writer.write(record + "\n");
            record = OFController.getInstance().getSwitch(dpId).getCurrentTime()+1 + "," + 0;
            writer.write(record + "\n");
            writer.flush();
            writer.close();

        }catch(IOException e){
            e.printStackTrace();
        }

    }

}
