package com.ayyoob.sdn.of.simulator.apps;

import com.ayyoob.sdn.of.simulator.*;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.*;
import java.nio.file.Paths;
import java.util.*;

public class IoTDeviceFlowBuilder implements ControllerApp {

    private static final int COMMON_FLOW_PRIORITY = 1000;
    private static final int D2G_DYNAMIC_FLOW_PRIORITY = 810;
    private static final int D2G_PRIORITY = 800;
    private static final int G2D_DYNAMIC_FLOW_PRIORITY = 710;
    private static final int G2D_PRIORITY = 700;
    private static final int L2D_DYNAMIC_FLOW_PRIORITY = 610;
    private static final int L2D_PRIORITY = 600;

    private static final long MAX_FLOWS_PER_DEVICE = 5;
    private static final int THRESHOLD_FOR_DYNAMIC_IP_FLOWS = 3;
    private static final int MIN_FLOW_IMPACT_THRESHOLD = 5; //percentage
    private static final long MIN_TIME_FOR_FLOWS_MILLI_SECONDS = 120000;

    private static Map<String, Set<String>> deviceDnsIPsMap = new HashMap<String, Set<String>>();
    private static Map<OFFlow, Long> deviceFlowTimeMap = new HashMap<OFFlow, Long>();
    private static Map<String, long[]> deviceFlowPacketCountBeenRemoved = new HashMap<String, long[]>();
    private static boolean enabled = true;
    private static List<String> devices =new ArrayList<String>();

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

        if (srcMac.equals(ofSwitch.getMacAddress()) && packet.getIpProto().equals(Constants.UDP_PROTO)
                && packet.getSrcPort().equals(Constants.DNS_PORT)) {
            Set<String> dnsIPs = deviceDnsIPsMap.get(destMac);
            if (dnsIPs == null) {
                dnsIPs = new HashSet<String>();
            }
            dnsIPs.addAll(packet.getDnsAnswers());
            deviceDnsIPsMap.put(destMac, dnsIPs);
        } else {

            String dstIp = packet.getDstIp();
            String srcIp = packet.getSrcIp();
            String protocol = packet.getIpProto();
            String srcPort = packet.getSrcPort();
            String dstPort = packet.getDstPort();

            if (protocol.equals(Constants.TCP_PROTO) || protocol.equals(Constants.UDP_PROTO)) {
                // Device 2 Gateway flow
                if (destMac.equals(ofSwitch.getMacAddress()) && Integer.parseInt(dstPort) != 53
                        && Integer.parseInt(dstPort) != 123) {
                    String deviceMac = srcMac;

                    if (!dstIp.equals(ofSwitch.getIp())) {
                        Set<String> dnsIPs = deviceDnsIPsMap.get(deviceMac);
                        if (dnsIPs != null && deviceDnsIPsMap.get(deviceMac).contains(dstIp)) {
                            OFFlow ofFlow = new OFFlow();
                            ofFlow.setSrcMac(deviceMac);
                            ofFlow.setDstMac(ofSwitch.getMacAddress());
                            ofFlow.setDstPort(dstPort);
                            ofFlow.setIpProto(protocol);
                            ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                            ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
                            ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                            //OFController.getInstance().addFlow(dpId, ofFlow);
                            long packetCountTransmitted = 0;
                            List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac, D2G_DYNAMIC_FLOW_PRIORITY);
                            for (OFFlow flow : deviceFlows) {
                                if ((!flow.getDstIp().equals(dstIp) && flow.getIpProto().equals(protocol))
                                        && flow.getDstPort().equals(dstPort)) {
                                    packetCountTransmitted += flow.getPacketCount();
                                    removeFlow(dpId, flow, deviceMac);
                                }
                            }
                            long count[] = deviceFlowPacketCountBeenRemoved.get(deviceMac);
                            count[0] = count[0] - packetCountTransmitted;
                            deviceFlowPacketCountBeenRemoved.put(deviceMac, count);
                            ofFlow.setPacketCount(packetCountTransmitted);
                            addFlow(dpId, ofFlow, deviceMac);
                        } else {
                            OFFlow ofFlow = new OFFlow();
                            ofFlow.setSrcMac(deviceMac);
                            ofFlow.setDstMac(ofSwitch.getMacAddress());
                            ofFlow.setDstPort(dstPort);
                            ofFlow.setDstIp(dstIp);
                            ofFlow.setIpProto(protocol);
                            ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
                            ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
                            ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
                            List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac, D2G_DYNAMIC_FLOW_PRIORITY);
                            List<OFFlow> dynamicFlowsWithDifferentIps = new ArrayList<OFFlow>();
                            for (OFFlow flow : deviceFlows) {
                                if ((!flow.getDstIp().equals(dstIp) && flow.getIpProto().equals(protocol))
                                        && flow.getDstPort().equals(dstPort)) {
                                    dynamicFlowsWithDifferentIps.add(flow);
                                }
                            }
                            long packetCountTransmitted = 0;
                            if (dynamicFlowsWithDifferentIps.size() >= THRESHOLD_FOR_DYNAMIC_IP_FLOWS) {
                                for (OFFlow flow : deviceFlows) {
                                    packetCountTransmitted += flow.getPacketCount();
                                    removeFlow(dpId, flow, deviceMac);
                                }
                                long count[] = deviceFlowPacketCountBeenRemoved.get(deviceMac);
                                count[0] = count[0] - packetCountTransmitted;
                                deviceFlowPacketCountBeenRemoved.put(deviceMac, count);
                                ofFlow.setPacketCount(packetCountTransmitted);
                                ofFlow.setDstIp("*");
                            }
                            addFlow(dpId, ofFlow, deviceMac);
                        }

                    }
                    // Gateway to Device
                } else if (srcMac.equals(ofSwitch.getMacAddress()) && Integer.parseInt(srcPort) != 53
                        && Integer.parseInt(srcPort) != 123) {
                    if (!srcIp.equals(ofSwitch.getIp())) {
                        String deviceMac = destMac;
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
                } else if ((!srcMac.equals(ofSwitch.getMacAddress())) && (!destMac.equals(ofSwitch.getMacAddress()))) {
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

    private void addFlow(String dpId, OFFlow ofFlow, String deviceMac) {
        List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac, ofFlow.getPriority());
        if (deviceFlows.size() < MAX_FLOWS_PER_DEVICE) {
            deviceFlowTimeMap.put(ofFlow, OFController.getInstance().getSwitch(dpId).getCurrentTime());
            OFController.getInstance().addFlow(dpId, ofFlow);
        } else {
            OFFlow tobeRemoved = null;
            long totalPacket = getTotalPacketCount(dpId, deviceMac, ofFlow.getPriority());

            long count[] = deviceFlowPacketCountBeenRemoved.get(deviceMac);
            if (ofFlow.getPriority() == D2G_DYNAMIC_FLOW_PRIORITY) {
                totalPacket = totalPacket + count[0];
            } else if (ofFlow.getPriority() == G2D_DYNAMIC_FLOW_PRIORITY) {
                totalPacket = totalPacket + count[1];
            } else if (ofFlow.getPriority() == L2D_DYNAMIC_FLOW_PRIORITY) {
                totalPacket = totalPacket + count[2];
            }

            int flowsConsideredForRemoval = 0;
            for (OFFlow flow : deviceFlows) {

                long currentTime = OFController.getInstance().getSwitch(dpId).getCurrentTime();
                long flowInitializedTime = deviceFlowTimeMap.get(flow);
                if (currentTime - flowInitializedTime > MIN_TIME_FOR_FLOWS_MILLI_SECONDS) {
                    if (tobeRemoved == null) {
                        Double flowImpact = (flow.getPacketCount() * 1.0) / totalPacket;
                        if (MIN_FLOW_IMPACT_THRESHOLD > (flowImpact * 100)) {
                            tobeRemoved = flow;
                            flowsConsideredForRemoval++;
                        }
                    } else {
                        flowsConsideredForRemoval++;
                        Double flowImpact = (flow.getPacketCount() * 1.0) / totalPacket;
                        Double tobeRemovedFlowImpact = (tobeRemoved.getPacketCount() * 1.0) / totalPacket;
                        if (tobeRemovedFlowImpact > flowImpact) {
                            tobeRemoved = flow;
                        }
                    }
                }
            }
            if (tobeRemoved != null && flowsConsideredForRemoval > 1) {
                removeFlow(dpId, tobeRemoved, deviceMac);
                deviceFlowTimeMap.put(ofFlow, OFController.getInstance().getSwitch(dpId).getCurrentTime());
                OFController.getInstance().addFlow(dpId, ofFlow);
            }

        }
    }

    private void removeFlow(String dpId, OFFlow ofFlow, String deviceMac) {

        deviceFlowTimeMap.remove(ofFlow);

        long count[] = deviceFlowPacketCountBeenRemoved.get(deviceMac);
        if (ofFlow.getPriority() == D2G_DYNAMIC_FLOW_PRIORITY) {
            count[0] = count[0] + ofFlow.getPacketCount();
        } else if (ofFlow.getPriority() == G2D_DYNAMIC_FLOW_PRIORITY) {
            count[1] = count[1] + ofFlow.getPacketCount();
        } else if (ofFlow.getPriority() == L2D_DYNAMIC_FLOW_PRIORITY) {
            count[2] = count[2] + ofFlow.getPacketCount();
        }
        deviceFlowPacketCountBeenRemoved.put(deviceMac, count);
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

    public long getTotalPacketCount(String dpId, String deviceMac, int priority) {
        long totalPacketCount = 0;

        List<OFFlow> deviceFlows = getActiveFlows(dpId, deviceMac);
        for (OFFlow ofFlow : deviceFlows) {
            if (ofFlow.getPriority() == priority || ofFlow.getPriority() == (priority - 10)) {
                totalPacketCount = totalPacketCount + ofFlow.getPacketCount();
            }
        }

        return totalPacketCount;
    }

    public void initializeDeviceFlows(String dpId, String deviceMac, String gwMac) {
        //DNS
        OFFlow ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac(gwMac);
        ofFlow.setDstPort(Constants.DNS_PORT);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(COMMON_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(gwMac);
        ofFlow.setDstMac(deviceMac);
        ofFlow.setSrcPort(Constants.DNS_PORT);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(COMMON_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        OFController.getInstance().addFlow(dpId, ofFlow);

        //NTP
        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac(gwMac);
        ofFlow.setDstPort(Constants.NTP_PORT);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(COMMON_FLOW_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(gwMac);
        ofFlow.setDstMac(deviceMac);
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
        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        OFController.getInstance().addFlow(dpId, ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setIpProto(Constants.ICMP_PROTO);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(L2D_PRIORITY + 1);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        OFController.getInstance().addFlow(dpId, ofFlow);

        long flowCount[] = {0, 0, 0};
        deviceFlowPacketCountBeenRemoved.put(deviceMac, flowCount);
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
                long totalPacketCount = getTotalPacketCount(dpId, deviceMac, D2G_DYNAMIC_FLOW_PRIORITY);
                List<OFFlow> ofFlows = getActiveFlows(dpId, deviceMac, D2G_DYNAMIC_FLOW_PRIORITY);
                for (OFFlow ofFlow : ofFlows) {
                    Double flowImpact = (ofFlow.getPacketCount() * 1.0) / totalPacketCount;
                    if ((flowImpact * 100) < MIN_FLOW_IMPACT_THRESHOLD) {
                        flowsTobeRemoved.add(ofFlow);
                    } else {
                        if (!ofFlow.getDstIp().equals("*")) {
                            if (deviceDnsIPsMap.get(deviceMac).contains(ofFlow.getDstIp())) {
                                ofFlow.setDstIp("*");
                            }
                        }
                        OFFlow reverseFlow = ofFlow.copy();
                        reverseFlow.setSrcMac(ofFlow.getDstMac());
                        reverseFlow.setDstMac(ofFlow.getSrcMac());
                        reverseFlow.setSrcPort(ofFlow.getDstPort());
                        reverseFlow.setDstPort(ofFlow.getSrcPort());
                        flowsTobeAdded.add(reverseFlow);
                    }
                }


                totalPacketCount = getTotalPacketCount(dpId, deviceMac, G2D_DYNAMIC_FLOW_PRIORITY);
                ofFlows = getActiveFlows(dpId, deviceMac, G2D_DYNAMIC_FLOW_PRIORITY);
                for (OFFlow ofFlow : ofFlows) {
                    Double flowImpact = (ofFlow.getPacketCount() * 1.0) / totalPacketCount;
                    if ((flowImpact * 100) < MIN_FLOW_IMPACT_THRESHOLD) {
                        flowsTobeRemoved.add(ofFlow);
                    } else {
                        OFFlow reverseFlow = ofFlow.copy();
                        reverseFlow.setSrcMac(ofFlow.getDstMac());
                        reverseFlow.setDstMac(ofFlow.getSrcMac());
                        reverseFlow.setSrcPort(ofFlow.getDstPort());
                        reverseFlow.setDstPort(ofFlow.getSrcPort());
                        flowsTobeAdded.add(reverseFlow);
                    }
                }

                totalPacketCount = getTotalPacketCount(dpId, deviceMac, L2D_DYNAMIC_FLOW_PRIORITY);
                ofFlows = getActiveFlows(dpId, deviceMac, L2D_DYNAMIC_FLOW_PRIORITY);
                for (OFFlow ofFlow : ofFlows) {
                    Double flowImpact = (ofFlow.getPacketCount() * 1.0) / totalPacketCount;
                    if ((flowImpact * 100) < MIN_FLOW_IMPACT_THRESHOLD) {
                        flowsTobeRemoved.add(ofFlow);
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
                            + "result" + File.separator + deviceMac + ".csv", "UTF-8");
                    ofFlows = getActiveFlows(dpId, deviceMac);
                    if (ofFlows.size() > 0) {
                        System.out.println("Device : " + deviceMac);
                        boolean first = true;
                        for (OFFlow ofFlow : ofFlows) {
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
        }

    }
}
