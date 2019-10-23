package com.ayyoob.sdn.of.simulator;

import com.ayyoob.sdn.of.simulator.apps.ControllerApp;
import com.ayyoob.sdn.of.simulator.apps.StatListener;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;

import java.io.*;
import java.lang.reflect.Constructor;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeoutException;

public class AttackDetectSimulator {

    private static String devicedetails =
//            "44:65:0d:56:cc:d3,amazonEchoMud.json,amazonEcho\n"+
//                    "00:17:88:2b:9a:25,HueBulbMud.json,HueBulb\n" +
//                    "74:c6:3b:29:d7:1d,ihomepowerplugMud.json,ihomepowerplug\n" +
//                    "d0:73:d5:01:83:08,lifxbulbMud.json,lifxbulb\n" +
//                    "70:ee:50:18:34:43,NetatmoCameraMud.json,NetatmoCamera\n" +
//                    "50:c7:bf:00:56:39,tplinkplugMud.json,tplinkplug\n" +
//                    "ec:1a:59:83:28:11,wemomotionMud.json,wemomotion\n" +
//                    "ec:1a:59:79:f4:89,wemoswitchMud.json,wemoswitch\n" +
//            "00:16:6c:ab:6b:88,samsungsmartcamMud.json,samsungsmartcam"+
                    "f4:f5:d8:8f:0a:3c,chromecastUltraMud.json,chromecast"+

                    "";

    public static void main(String[] args) throws Exception {

        System.out.println("Working Directory is set to:" + Paths.get(".").toAbsolutePath().normalize().toString());

        JSONParser parser = new JSONParser();
        ClassLoader classLoader = AttackDetectSimulator.class.getClassLoader();
        File file = new File(classLoader.getResource("apps/simulator_config.json").getFile());
        Object obj = parser.parse(new FileReader(file));

        JSONObject jsonObject = (JSONObject) obj;

        String pcapLocation = "/Users/ayyoobhamza/Desktop/unsw/6-machineoptimize/pcap/";
        boolean inspectFileWrite = (boolean) jsonObject.get("inspectFileWrite");
        String inspectPcapFileName = (String) jsonObject.get("inspectFileName");
        String currentPath = Paths.get(".").toAbsolutePath().normalize().toString();

        File workingDirectory = new File(currentPath + File.separator + "result");
        if (!workingDirectory.exists()) {
            workingDirectory.mkdir();
        }
        inspectPcapFileName = currentPath + File.separator + "result" + File.separator + inspectPcapFileName;
        JSONObject switchConfig = (JSONObject) jsonObject.get("switchConfig");
        String dpId = (String) switchConfig.get("macAddress");
        String macAddress = (String) switchConfig.get("macAddress");
        String ipAddress = (String) switchConfig.get("ipAddress");

        JSONArray modules = (JSONArray) jsonObject.get("modules");
        JSONObject moduleConfig = (JSONObject) jsonObject.get("moduleConfig");

        final OFSwitch ofSwitch = new OFSwitch(dpId, macAddress, ipAddress);


        for (String dt : devicedetails.split("\n")) {
            OFController.getInstance().addSwitch(ofSwitch);
            String deviceMac = dt.split(",")[0];
            String mudName = dt.split(",")[1];
//            String folderName = dt.split(",")[2].replace(".json", "");
            String newPcapLocation = pcapLocation + deviceMac.replace(":", "") + ".pcap";
            Iterator<String> iterator = modules.iterator();
            while (iterator.hasNext()) {
                String fqClassName = iterator.next();
                String spilitClassName[] = fqClassName.split("\\.");
                String className = spilitClassName[spilitClassName.length-1];
                JSONObject arg = (JSONObject) moduleConfig.get(className);
                arg.remove("device");
                arg.remove("mud");
                arg.put("mud", "/Users/ayyoobhamza/Desktop/unsw/6-machineoptimize/profiles/" + mudName);
                arg.put("device", deviceMac);

                Class<?> clazz = Class.forName(fqClassName);
                Constructor<?> ctor = clazz.getConstructor();
                ControllerApp controllerApp = (ControllerApp) ctor.newInstance();

                OFController.getInstance().registerApps(controllerApp, arg);
            }
            JSONArray statModules = (JSONArray) jsonObject.get("statModules");
            iterator = statModules.iterator();
            while (iterator.hasNext()) {
                String fqClassName = iterator.next();
                String spilitClassName[] = fqClassName.split("\\.");
                String className = spilitClassName[spilitClassName.length-1];
                JSONObject arg = (JSONObject) moduleConfig.get(className);
                arg.remove("device");
                arg.remove("mud");
                arg.put("mud", "/Users/ayyoobhamza/Desktop/unsw/6-machineoptimize/profiles/" + mudName);
                arg.put("device", deviceMac);

                Class<?> clazz = Class.forName(fqClassName);
                Constructor<?> ctor = clazz.getConstructor();
                StatListener statListener = (StatListener) ctor.newInstance();

                OFController.getInstance().registerStatListeners(statListener, arg);
            }

            long pktcount= processPcap(newPcapLocation, ofSwitch, inspectFileWrite, inspectPcapFileName);
            OFController.getInstance().complete();
            String stats = OFController.getInstance().getStats() + "\n totalPacketCount: " + pktcount;
            OFController.getInstance().removeApps();
            OFController.getInstance().removeStatsListener();
            OFController.getInstance().removeSwitch();
            ofSwitch.clearAllFlows();

            String flowfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":",
                    "") +
                    "perfstats.csv";
            try{
                FileWriter fw=new FileWriter(flowfilename);
                fw.write(stats);
                fw.close();
            }catch(Exception e){System.out.println(e);}

            File f = new File(currentPath + File.separator + "result" + File.separator +
                    "DevFlowMachineData" + File.separator + deviceMac
                    .replace(":", ""));
            File currDir = new File(currentPath + File.separator + "result");
            if (!f.exists()) {
                f.mkdir();
                move(f, currDir);
            }


        }


    }

    private static void move(File toDir, File currDir) {
        File[] files = currDir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                if (name.contains(".txt") || name.contains(".csv")) {
                    return true;
                }
                return false;
            }
        });
        for (File file : files){
            file.renameTo(new File(toDir, file.getName()));
        }
    }

    private static long processPcap(String pcapLocation, OFSwitch ofSwitch, boolean inspectFileWrite, String
            inspectPcapFileName
    ) throws PcapNativeException, NotOpenException {
        boolean firstPacket = false;
        long startTimestamp = 0;
        long endTimestamp= 0;
        long totalPacketCount=0;
        long sumPacketProcessingTime=0;
        PcapDumper dumper = null;
        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(pcapLocation, PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(pcapLocation);
        }
        if (inspectFileWrite) {
            dumper = handle.dumpOpen(inspectPcapFileName);
        }
        try {
            int i =0;
            while (true) {
                i++;
                Packet packet;
                try {
                    packet = handle.getNextPacketEx();
                } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
                    continue;
                }

                totalPacketCount++;
                //System.out.println(packet);
                SimPacket simPacket = new SimPacket();
                simPacket.setData(packet.getRawData());
                if (!firstPacket) {
                    startTimestamp = handle.getTimestamp().getTime();
                    firstPacket=true;
                }

                endTimestamp =handle.getTimestamp().getTime();
                simPacket.setTimestamp(handle.getTimestamp().getTime());
                try {
                    EthernetPacket.EthernetHeader header = (EthernetPacket.EthernetHeader) packet.getHeader();
                    if (header == null) {
                        continue;
                    }
                    simPacket.setSrcMac(header.getSrcAddr().toString());
                    simPacket.setDstMac(header.getDstAddr().toString());
                    simPacket.setSize(packet.length());
                    simPacket.setEthType(header.getType().valueAsString());
                    if (header.getType() == EtherType.IPV4 || header.getType() == EtherType.IPV6) {
                        String protocol;
                        IpV6Packet ipV6Packet = null;
                        IpV4Packet ipV4Packet = null;
                        if (header.getType() == EtherType.IPV4) {
                            ipV4Packet = (IpV4Packet) packet.getPayload();
                            IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();
                            simPacket.setSrcIp(ipV4Header.getSrcAddr().getHostAddress());
                            simPacket.setDstIp(ipV4Header.getDstAddr().getHostAddress());
                            simPacket.setIpProto(ipV4Header.getProtocol().valueAsString());
                            protocol = ipV4Header.getProtocol().valueAsString();
                        } else {
                            ipV6Packet = (IpV6Packet) packet.getPayload();
                            IpV6Packet.IpV6Header ipV6Header = ipV6Packet.getHeader();
                            simPacket.setSrcIp(ipV6Header.getSrcAddr().getHostAddress());
                            simPacket.setDstIp(ipV6Header.getDstAddr().getHostAddress());
                            simPacket.setIpProto(ipV6Header.getProtocol().valueAsString());
                            protocol = ipV6Header.getProtocol().valueAsString();
                        }
                        if (protocol.equals(IpNumber.TCP.valueAsString()) ) {
                            TcpPacket tcpPacket;
                            if (header.getType() == EtherType.IPV4) {
                                tcpPacket = (TcpPacket) ipV4Packet.getPayload();
                            } else {
                                tcpPacket = (TcpPacket) ipV6Packet.getPayload();
                            }
                            simPacket.setSrcPort(tcpPacket.getHeader().getSrcPort().valueAsString());
                            simPacket.setDstPort(tcpPacket.getHeader().getDstPort().valueAsString());
                            simPacket.setTcpFlag(tcpPacket.getHeader().getSyn(),tcpPacket.getHeader().getAck()
                                    ,tcpPacket.getHeader().getRst());

                        } else if (protocol.equals(IpNumber.UDP.valueAsString()) ) {
                            UdpPacket udpPacket;
                            if (header.getType() == EtherType.IPV4) {
                                udpPacket = (UdpPacket) ipV4Packet.getPayload();
                            } else {
                                udpPacket = (UdpPacket) ipV6Packet.getPayload();
                            }
                            simPacket.setSrcPort(udpPacket.getHeader().getSrcPort().valueAsString());
                            simPacket.setDstPort(udpPacket.getHeader().getDstPort().valueAsString());

                            if (udpPacket.getHeader().getDstPort().valueAsString().equals(Constants.DNS_PORT)) {
                                try {
                                    DnsPacket dnsPacket = udpPacket.get(DnsPacket.class);
//                                    dnsPacket.getHeader().getAdditionalInfo().get(0).getDataType().compareTo()
                                    List<DnsQuestion> dnsQuestions = dnsPacket.getHeader().getQuestions();
                                    if (dnsQuestions.size() > 0) {
                                        simPacket.setDnsQname(dnsQuestions.get(0).getQName().getName());
                                    }
                                } catch (NullPointerException e) {
                                    //ignore packet that send to port 53
                                }
                                //System.out.println(new String(packet.getData()));
                            } else if (udpPacket.getHeader().getSrcPort().valueAsString().equals(Constants.DNS_PORT)) {
                                DnsPacket dnsPacket = udpPacket.get(DnsPacket.class);
                                try {
                                    List<DnsResourceRecord> dnsResourceRecords = dnsPacket.getHeader().getAnswers();
                                    List<String> answers = new ArrayList<String>();
                                    simPacket.setDnsQname(dnsPacket.getHeader().getQuestions().get(0).getQName().getName());
                                    for (DnsResourceRecord record : dnsResourceRecords) {
                                        try {
                                            DnsRDataA dnsRDataA = (DnsRDataA) record.getRData();
                                            answers.add(dnsRDataA.getAddress().getHostAddress());
                                        } catch (ClassCastException ex) {
                                            //ignore
                                        }

                                    }
                                    simPacket.setDnsAnswers(answers);
                                }catch (NullPointerException | IndexOutOfBoundsException e) {
                                    //System.out.println(packet);
                                    //ignore
                                }
                            }
                        } else if (protocol.equals(IpNumber.ICMPV4.valueAsString())) {
                            IcmpV4CommonPacket icmpV4CommonPacket = (IcmpV4CommonPacket) ipV4Packet.getPayload();
                            simPacket.setIcmpType(icmpV4CommonPacket.getHeader().getType().valueAsString());
                            simPacket.setIcmpCode(icmpV4CommonPacket.getHeader().getCode().valueAsString());
                            simPacket.setSrcPort("*");
                            simPacket.setDstPort("*");
                        } else if (protocol.equals(IpNumber.ICMPV6.valueAsString())) {
                            IcmpV6CommonPacket icmpV6CommonPacket = (IcmpV6CommonPacket) ipV6Packet.getPayload();
                            simPacket.setIcmpType(icmpV6CommonPacket.getHeader().getType().valueAsString());
                            simPacket.setIcmpCode(icmpV6CommonPacket.getHeader().getCode().valueAsString());
                            simPacket.setSrcPort("*");
                            simPacket.setDstPort("*");
                        } else {
                            simPacket.setSrcPort("*");
                            simPacket.setDstPort("*");
                        }
                    }
                    long startTime = System.currentTimeMillis();
                    ofSwitch.transmit(simPacket);
                    if (inspectFileWrite && simPacket.isInspected()) {
                        dumper.dump(packet);
                    }
                    long endTime = System.currentTimeMillis();
                    sumPacketProcessingTime = sumPacketProcessingTime + (endTime-startTime);
                } catch (ClassCastException e) {
                    //ignorewi
                }
//                simPacket.print();
            }

        } catch (EOFException e) {
        } catch (NotOpenException e) {
            e.printStackTrace();
        } catch (TimeoutException e) {
            e.printStackTrace();
        }
        System.out.println("Average Packet Processing Time " + (sumPacketProcessingTime *1.0)/totalPacketCount);
        System.out.println("Timetaken: " + (endTimestamp-startTimestamp) + ", Total Packets: " + totalPacketCount);
        return totalPacketCount;
    }

}
