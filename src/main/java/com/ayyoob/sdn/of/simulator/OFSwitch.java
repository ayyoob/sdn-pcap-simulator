package com.ayyoob.sdn.of.simulator;


import com.ayyoob.sdn.of.simulator.apps.StatListener;

import java.util.*;

public class OFSwitch {
    private String macAddress;
    private String ip;
    private String dpid;
    private long currentTime=0;
    private long lastPacketTime=0;
    private LinkedList<OFFlow> ofFlows = new LinkedList<OFFlow>();
    private static String ignoreMacPrefix[] = {"01:00:5E", "33:33", "FF:FF:FF"};

    private Map<String, Set<OFFlow>> srcMac = new HashMap<>();
    private Map<String, Set<OFFlow>>  dstMac = new HashMap<>();
    private Map<String, Set<OFFlow>>  ethType= new HashMap<>();
    private Map<String, Set<OFFlow>>  srcIp= new HashMap<>();
    private Map<String, Set<OFFlow>>  dstIp= new HashMap<>();
    private Map<String, Set<OFFlow>>  ipProto= new HashMap<>();
    private Map<String, Set<OFFlow>>  srcPort= new HashMap<>();
    private Map<String, Set<OFFlow>>  dstPort= new HashMap<>();
    private Map<String, Set<OFFlow>>  icmpType= new HashMap<>();
    private Map<String, Set<OFFlow>>  icmpCode= new HashMap<>();

    public void transmit(SimPacket packet) {
        if (packet.getSrcIp() != null && packet.getSrcIp().equals("192.168.1.2") ) {
            int x = 3;
        }

        currentTime = packet.getTimestamp();
        if (lastPacketTime > currentTime) {
            return;
        }
        cleanIdleFlows();
        for (StatListener statListener : OFController.getInstance().getStatListeners()) {
            statListener.process(dpid, packet.getTimestamp());
        }
        OFFlow flow = getMatchingFlow(packet);
        if (flow.getOfAction() == OFFlow.OFAction.MIRROR_TO_CONTROLLER) {
            OFController.getInstance().receive(dpid, packet);
            packet.setInspected(true);
        }
        flow.setVolumeTransmitted(flow.getVolumeTransmitted() + packet.getSize());
        flow.setPacketCount(flow.getPacketCount() + 1);
        flow.setLastPacketTransmittedTime(packet.getTimestamp());
        lastPacketTime = packet.getTimestamp();
    }

    public OFSwitch(String dpid, String macAddress, String ip) {
        this.dpid = dpid;
        this.macAddress = macAddress.toLowerCase();
        this.ip = ip;
        clearAllFlows();
    }

    private OFFlow getDefaultFlow() {
        OFFlow defaultFlow = new OFFlow();
        defaultFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        defaultFlow.setPriority(1);
        return defaultFlow;
    }

    public long getCurrentTime() {
        return currentTime;
    }

    public void setCurrentTime(long currentTime) {
        this.currentTime = currentTime;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getDpid() {
        return dpid;
    }

    public void setDpid(String dpid) {
        this.dpid = dpid;
    }

    public List<OFFlow> getAllFlows() {
        return ofFlows;
    }

    public void addFlow(OFFlow flow){
        boolean exist=false;
        for (int i = 0 ; i < ofFlows.size(); i++) {
            OFFlow currentFlow = ofFlows.get(i);
            if (currentFlow.equals(flow)) {
                exist = true;
                break;
            }
        }
        if (!exist) {
            for (int i = 0 ; i < ofFlows.size(); i++) {
                OFFlow currentFlow = ofFlows.get(i);

                if (flow.getPriority() >= currentFlow.getPriority()) {
                    if (i == 0) {
                        ofFlows.addFirst(flow);
                        break;
                    } else {
                        ofFlows.add(i, flow);
                        break;
                    }
                } else if (flow.getPriority() <= 1) {
                    if (currentFlow.equals(getDefaultFlow())) {
                        if (i == 0) {
                            ofFlows.addFirst(flow);
                            break;
                        } else {
                            ofFlows.add(i, flow);
                            break;
                        }
                    }
                }

            }

            //add
            addEntry(srcMac, flow, flow.getSrcMac());
            addEntry(dstMac, flow, flow.getDstMac());
            addEntry(ethType, flow, flow.getEthType());
            addEntry(srcIp, flow, flow.getSrcIp());
            addEntry(dstIp, flow, flow.getDstIp());
            addEntry(ipProto, flow, flow.getIpProto());
            addEntry(srcPort, flow, flow.getSrcPort());
            addEntry(dstPort, flow, flow.getDstPort());
            addEntry(icmpType, flow, flow.getIcmpType());
            addEntry(icmpCode, flow, flow.getIcmpCode());
        }
    }

    private void addEntry(Map<String, Set<OFFlow>> map, OFFlow flow, String keyValue) {
        if (map.get(keyValue) == null) {
            Set<OFFlow> flowSet = new HashSet<>();
            flowSet.add(flow);
            map.put(keyValue, flowSet);
        }else {
            map.get(keyValue).add(flow);
        }
    }



    public void removeFlow(OFFlow flow) {
        for (int i = 0 ; i < ofFlows.size(); i++) {
            OFFlow currentFlow = ofFlows.get(i);
            if (currentFlow.equals(flow)) {
                ofFlows.remove(i);
            }
        }

        removeEntry(srcMac, flow, flow.getSrcMac());
        removeEntry(dstMac, flow, flow.getDstMac());
        removeEntry(ethType, flow, flow.getEthType());
        removeEntry(srcIp, flow, flow.getSrcIp());
        removeEntry(dstIp, flow, flow.getDstIp());
        removeEntry(ipProto, flow, flow.getIpProto());
        removeEntry(srcPort, flow, flow.getSrcPort());
        removeEntry(dstPort, flow, flow.getDstPort());
        removeEntry(icmpType, flow, flow.getIcmpType());
        removeEntry(icmpCode, flow, flow.getIcmpCode());
    }

    private void removeEntry(Map<String, Set<OFFlow>> map, OFFlow flow, String keyValue) {
        if (keyValue.equals("*")) {
            for (String key : map.keySet()) {
                map.get(key).remove(flow);
            }
        } else {
            map.get(keyValue).remove(flow);
        }
    }

    public void clearAllFlows() {
        ofFlows = new LinkedList<OFFlow>();
        OFFlow flow = getDefaultFlow();
        ofFlows.add(flow);

        addEntry(srcMac, flow, flow.getSrcMac());
        addEntry(dstMac, flow, flow.getDstMac());
        addEntry(ethType, flow, flow.getEthType());
        addEntry(srcIp, flow, flow.getSrcIp());
        addEntry(dstIp, flow, flow.getDstIp());
        addEntry(ipProto, flow, flow.getIpProto());
        addEntry(srcPort, flow, flow.getSrcPort());
        addEntry(dstPort, flow, flow.getDstPort());
        addEntry(icmpType, flow, flow.getIcmpType());
        addEntry(icmpCode, flow, flow.getIcmpCode());

        currentTime = 0;
        lastPacketTime = 0;
    }


    public void removeFlows(int priority) {
        List<Integer> tobeRemoved = new ArrayList();
        for (int i = 0 ; i < ofFlows.size(); i++) {
            OFFlow currentFlow = ofFlows.get(i);
            if (currentFlow.getPriority() == priority) {
                tobeRemoved.add(i);
            }
        }

        for (int i = tobeRemoved.size() - 1; i >= 0; i--) {
            OFFlow flow = ofFlows.get(tobeRemoved.get(i));
            removeEntry(srcMac, flow, flow.getSrcMac());
            removeEntry(dstMac, flow, flow.getDstMac());
            removeEntry(ethType, flow, flow.getEthType());
            removeEntry(srcIp, flow, flow.getSrcIp());
            removeEntry(dstIp, flow, flow.getDstIp());
            removeEntry(ipProto, flow, flow.getIpProto());
            removeEntry(srcPort, flow, flow.getSrcPort());
            removeEntry(dstPort, flow, flow.getDstPort());
            removeEntry(icmpType, flow, flow.getIcmpType());
            removeEntry(icmpCode, flow, flow.getIcmpCode());
            ofFlows.remove(tobeRemoved.get(i));
        }
    }

    private Set<OFFlow> getEntries(Map<String, Set<OFFlow>> map, String keyValue) {

        Set<OFFlow> result = new HashSet<>();
        if (map.get("*") != null) {
            result = new HashSet<>(map.get("*"));
        }
        if (map.get(keyValue) != null) {
            result.addAll(map.get(keyValue));
        }
        return result;
    }

    private Set<OFFlow> getMatchingSet(SimPacket packet) {
        Set<OFFlow> result = new HashSet<>(getEntries(srcMac, packet.getSrcMac()));
        result.retainAll(getEntries(dstMac, packet.getDstMac()));
        result.retainAll(getEntries(ethType, packet.getEthType()));
        result.retainAll(getEntries(ipProto, packet.getIpProto()));
        result.retainAll(getEntries(srcPort, packet.getSrcPort()));
        result.retainAll(getEntries(dstPort, packet.getDstPort()));
        result.retainAll(getEntries(icmpType, packet.getIcmpType()));
        result.retainAll(getEntries(icmpCode, packet.getIcmpCode()));
        return result;
    }

    private OFFlow getMatchingFlow(SimPacket packet) {

        Set<OFFlow> ofFlowSet = getMatchingSet(packet);
        OFFlow matchedFlow = null;
        for (OFFlow flow : ofFlowSet) {
            String srcIp=packet.getSrcIp() == null ? "*": packet.getSrcIp();
            String dstIp=packet.getDstIp() == null ? "*": packet.getDstIp();
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
            if (ipMatching ) {
                if (matchedFlow == null || matchedFlow.getPriority()<flow.getPriority()) {
                    matchedFlow = flow;
                }
            }
        }
        if (matchedFlow != null) {
            return matchedFlow;
        }
        System.out.println("SOMETHING FISHY .... !!!");
        ofFlowSet = getMatchingSet(packet);
        return ofFlows.getLast();
    }

//    private OFFlow getOldMatchingFlow(SimPacket packet) {
//
//
//        for (int i = 0 ; i < ofFlows.size(); i++) {
//
//            OFFlow flow = ofFlows.get(i);
//            String srcMac=packet.getSrcMac();
//            String dstMac=packet.getDstMac();
//            String ethType=packet.getEthType();
//            String vlanId="*";
//            String srcIp=packet.getSrcIp() == null ? "*": packet.getSrcIp();
//            String dstIp=packet.getDstIp() == null ? "*": packet.getDstIp();
//            String ipProto=packet.getIpProto()== null ? "*": packet.getIpProto();
//            String srcPort=packet.getSrcPort()== null ? "*": packet.getSrcPort();
//            String dstPort=packet.getDstPort()== null ? "*": packet.getDstPort();
//            String icmpCode=packet.getIcmpCode()== null ? "*": packet.getIcmpCode();
//            String icmpType=packet.getIcmpType()== null ? "*": packet.getIcmpType();
//            //TODO temporary for testing purposes
//
//            boolean condition = (srcMac.equals(flow.getSrcMac()) || flow.getSrcMac().equals("*"))&&
//                    (dstMac.equals(flow.getDstMac())  || flow.getDstMac().equals("*"))&&
//                    (ethType.equals(flow.getEthType()) || flow.getEthType().equals("*")) &&
//                    (vlanId.equals(flow.getVlanId())  || flow.getVlanId().equals("*"))&&
//                    (icmpType.equals(flow.getIcmpType())  || flow.getIcmpType().equals("*"))&&
//                    (icmpCode.equals(flow.getIcmpCode())  || flow.getIcmpCode().equals("*"))&&
//                    (ipProto.equals(flow.getIpProto())  || flow.getIpProto().equals("*"))&&
//                    (srcPort.equals(flow.getSrcPort())  || flow.getSrcPort().equals("*"))&&
//                    (dstPort.equals(flow.getDstPort()) || flow.getDstPort().equals("*"));
//
//            if (condition) {
//                boolean ipMatching ;
//                if (flow.getSrcIp().contains("/")) {
//                    String ip = flow.getSrcIp().split("/")[0];
//                    if (flow.getSrcIp().equals(Constants.LINK_LOCAL_MULTICAST_IP_RANGE)) {
//                        ip = "ff";
//                    }
//                    ipMatching = srcIp.startsWith(ip) || flow.getSrcIp().equals("*");
//                } else {
//                    ipMatching = (srcIp.equals(flow.getSrcIp())  || flow.getSrcIp().equals("*"));
//                }
//                if (flow.getDstIp()!=null) {
//                    if (flow.getDstIp().contains("/")) {
//                        String ip = flow.getDstIp().split("/")[0];
//                        if (flow.getDstIp().equals(Constants.LINK_LOCAL_MULTICAST_IP_RANGE)) {
//                            ip = "ff";
//                        }
//                        ipMatching = ipMatching && dstIp.startsWith(ip) || flow.getDstIp().equals("*");
//                    } else {
//                        ipMatching = ipMatching && (dstIp.equals(flow.getDstIp()) || flow.getDstIp().equals("*"));
//                    }
//                }
//                if (ipMatching) {
//                    return flow;
//                }
//            }
//        }
//        System.out.println("SOMETHING FISHY .... !!!");
//        return ofFlows.getLast();
//    }

    public void printFlows() {
        System.out.println(ofFlows.get(0).getFlowHeaderString());
        for (int i = 0 ; i < ofFlows.size(); i++) {
            System.out.println(ofFlows.get(i).getFlowString());
        }
    }

    private boolean isIgnored(String mac) {
        for (String prefix : ignoreMacPrefix) {
            if (mac.contains(prefix.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private void cleanIdleFlows() {
        for (int i = ofFlows.size()-1 ; i >= 0; i--) {
            OFFlow currentFlow = ofFlows.get(i);
            if (currentFlow.getIdleTimeOut() > 0 && (currentTime - currentFlow.getLastPacketTransmittedTime())
                    >= currentFlow.getIdleTimeOut()) {
                OFFlow flow = ofFlows.get(i);
                removeEntry(srcMac, flow, flow.getSrcMac());
                removeEntry(dstMac, flow, flow.getDstMac());
                removeEntry(ethType, flow, flow.getEthType());
                removeEntry(srcIp, flow, flow.getSrcIp());
                removeEntry(dstIp, flow, flow.getDstIp());
                removeEntry(ipProto, flow, flow.getIpProto());
                removeEntry(srcPort, flow, flow.getSrcPort());
                removeEntry(dstPort, flow, flow.getDstPort());
                removeEntry(icmpType, flow, flow.getIcmpType());
                removeEntry(icmpCode, flow, flow.getIcmpCode());

                ofFlows.remove(i);
            }
        }
    }



}
