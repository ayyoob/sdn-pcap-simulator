package com.ayyoob.sdn.of.simulator.apps.flow.collector;

import com.ayyoob.sdn.of.simulator.*;
import com.ayyoob.sdn.of.simulator.apps.StatListener;
import org.json.simple.JSONObject;

import java.io.*;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Proactive stats collector. This app collect stats based on the flows listed in proactiveFlows.txt
 */
public class SingleSwitchStatsCollector implements StatListener {

    private static boolean enabled = true;
    private static long summerizationTimeInMillis = 60000;
    private List<OFFlow> columns = new ArrayList<>();
    private long lastLogTime = 0;
    private String dpId;
    private List<String> data = new ArrayList<>();
    private static String filename;
    private static String flowIdfilename;

    @Override
    public void init(JSONObject jsonObject) {
        enabled = (Boolean) jsonObject.get("enabled");
        String outputFilename = ((String) jsonObject.get("filename")).toLowerCase();
        if (!enabled) {
            return;
        }
        summerizationTimeInMillis = ((Long) jsonObject.get("summerizationTimeInSeconds")) * 1000;
        dpId = (String) jsonObject.get("dpId");
        String currentPath = Paths.get(".").toAbsolutePath().normalize().toString();

        File workingDirectory = new File(currentPath + File.separator + "result");
        if (!workingDirectory.exists()) {
            workingDirectory.mkdir();
        }
        filename = currentPath + File.separator + "result" + File.separator + outputFilename + ".csv";
        flowIdfilename = currentPath + File.separator + "result" + File.separator + outputFilename + "_flowIds.csv";
        ClassLoader classLoader = Simulator.class.getClassLoader();
        File file = new File(classLoader.getResource("proactiveFlows.txt").getFile());
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                // process the line.
                //"srcMac,dstMac,ethType,vlanId,srcIp,dstIp,ipProto,srcPort,dstPort,priority"
                if (!line.isEmpty()) {
                    String vals[] = line.split(",");
                    OFFlow ofFlow = new OFFlow();
                    ofFlow.setSrcMac(vals[0]);
                    ofFlow.setDstMac(vals[1]);
                    ofFlow.setEthType(vals[2]);
                    ofFlow.setVlanId(vals[3]);
                    ofFlow.setSrcIp(vals[4]);
                    ofFlow.setDstIp(vals[5]);
                    ofFlow.setIpProto(vals[6]);
                    ofFlow.setSrcPort(vals[7]);
                    ofFlow.setDstPort(vals[8]);
                    ofFlow.setPriority(Integer.parseInt(vals[9]));
                    ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
                    columns.add(ofFlow);
                    OFController.getInstance().addFlow(dpId, ofFlow);
                }
            }
            String lineHeader = "timestamp";
            for (int i = 1; i <= columns.size(); i++) {
                lineHeader = lineHeader + "," + i;
            }

            if (columns.size() > 0) {
                try {
                    PrintWriter columnWriter = new PrintWriter(currentPath + File.separator
                            + "result" + File.separator + outputFilename + "_flow_meta.csv", "UTF-8");
                    boolean first = true;
                    for (int i = 1; i <= columns.size(); i++) {
                        if (first) {
                            columnWriter.println("flowId," + columns.get(i-1).getFlowHeaderWithoutFlowStat());
                            first = false;
                        }
                        columnWriter.println(i + "," + columns.get(i-1).getFlowStringWithoutFlowStat());
                    }
                    columnWriter.close();
                } catch (FileNotFoundException | UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
                PrintWriter writer = new PrintWriter(new BufferedWriter(
                        new FileWriter(filename)), true);
                writer.println(lineHeader);
                writer.close();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void process(String dpId, long timestamp) {
        if (!enabled) {
            return;
        }
        if (!this.dpId.equals(dpId)) {
            return;
        }

        long nextLogTime = 0;
        if (lastLogTime == 0) {
            lastLogTime = timestamp;
            return;
        }
        nextLogTime = lastLogTime + summerizationTimeInMillis;

        long currentTime = timestamp;
        if (currentTime >= nextLogTime) {
            lastLogTime = currentTime;
            data.add(currentTime + "," + getVolumeData());
//            while (currentTime >= nextLogTime) {
//                //writer.println(currentLogTime + "," + volumeData);
//                data.add(nextLogTime + "," + getVolumeData());
//
//                long iter = (currentTime - (nextLogTime+ summerizationTimeInMillis)) / summerizationTimeInMillis;
//                if (iter > 0) {
//                    for (int i = 0; i <iter; i++) {
//                        nextLogTime = nextLogTime + summerizationTimeInMillis;
//                        //writer.println(currentLogTime + "," + volumeData);
//                        data.add(nextLogTime + "," + getVolumeData());
//                    }
//                }
//                lastLogTime = nextLogTime;
//                nextLogTime = nextLogTime + summerizationTimeInMillis;
//            }

        }

        if (data.size() > 10000) {
            try {
                writeRaw(data);
                data.clear();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private String getVolumeData() {
        boolean first = true;
        StringBuilder volumeData = new StringBuilder();
        volumeData.append("");
        for (OFFlow ofFlow : columns) {
            OFFlow detectedFlow = null;
            List<OFFlow> flowStats = OFController.getInstance().getAllFlows(dpId);
            for (OFFlow flowStat : flowStats) {
                if (ofFlow.equals(flowStat)) {
                    detectedFlow = flowStat;
                    break;
                }
            }
            if (first) {
                if (detectedFlow != null) {
                    volumeData.append(detectedFlow.getVolumeTransmitted());
                    volumeData.append(",");
                    volumeData.append(detectedFlow.getPacketCount());
                } else {
                    volumeData.append(0);
                    volumeData.append(",");
                    volumeData.append(0);
                }
                first =false;
            } else {
                if (detectedFlow != null) {
                    volumeData.append(",");
                    volumeData.append(detectedFlow.getVolumeTransmitted());
                    volumeData.append(",");
                    volumeData.append(detectedFlow.getPacketCount());
                } else {
                    volumeData.append(",");
                    volumeData.append(0);
                    volumeData.append(",");
                    volumeData.append(0);
                }
            }

        }
        return volumeData.toString();
    }

//    private String getVolumeData() {
//        boolean first = true;
//        StringBuilder volumeData = new StringBuilder();
//        volumeData.append("");
//        for (OFFlow ofFlow : columns) {
//            OFFlow detectedFlow = null;
//            List<OFFlow> flowStats = OFController.getInstance().getAllFlows(dpId);
//            for (OFFlow flowStat : flowStats) {
//                if (ofFlow.equals(flowStat)) {
//                    detectedFlow = flowStat;
//                    break;
//                }
//            }
//            if (first) {
//                if (detectedFlow != null) {
//                    volumeData.append(detectedFlow.getVolumeTransmitted());
//                } else {
//                    volumeData.append(0);
//                }
//                first =false;
//            } else {
//                if (detectedFlow != null) {
//                    volumeData.append(",");
//                    volumeData.append(detectedFlow.getVolumeTransmitted());
//                } else {
//                    volumeData.append(",");
//                    volumeData.append(0);
//                }
//            }
//
//        }
//        return volumeData.toString();
//    }

    @Override
    public void complete() {
        if (!enabled) {
            return;
        }
        try {
            writeRaw(data);
            printFlowIds();
            boolean first = true;
            for (int i = 1; i <= columns.size(); i++) {
                if (first) {
                    System.out.println("flowId," + columns.get(i-1).getFlowHeaderString());
                    first = false;
                }
                System.out.println(i + "," + columns.get(i-1).getFlowString());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void printFlowIds() throws IOException {
        String allFlows = "allFlows";
        String lanFlows = "lanFlows";
        String wanFlows = "wanFlows";
        boolean first = true;
        for (int i = 0; i < columns.size(); i++) {
            OFFlow ofFlow = columns.get(i);
            if (ofFlow.getPriority() == 1000) {
                switch (ofFlow.getEthType()) {
                    case Constants.ETH_TYPE_IPV4:
                        if (Integer.parseInt(ofFlow.getIpProto()) == 1) {
                            if (ofFlow.getSrcMac().equals(OFController.getInstance().getSwitch(dpId).getMacAddress())) {
                                allFlows = allFlows + "," + "icmpDownV";
                                wanFlows = wanFlows + "," + "icmpDownV";
                                allFlows = allFlows + "," + "icmpDownP";
                                wanFlows = wanFlows + "," + "icmpDownP";
                            } else {
                                allFlows = allFlows + "," + "icmpUpV";
                                wanFlows = wanFlows + "," + "icmpUpV";
                                allFlows = allFlows + "," + "icmpUpP";
                                wanFlows = wanFlows + "," + "icmpUpP";
                            }
                        } else if (ofFlow.getIpProto().equals(Constants.UDP_PROTO)){
                            if (ofFlow.getSrcPort().equals("123")) {
                                allFlows = allFlows + "," + "ntpDownV";
                                wanFlows = wanFlows + "," + "ntpDownV";
                                allFlows = allFlows + "," + "ntpDownP";
                                wanFlows = wanFlows + "," + "ntpDownP";
                            } else if (ofFlow.getDstPort().equals("123")) {
                                allFlows = allFlows + "," + "ntpUpV";
                                wanFlows = wanFlows + "," + "ntpUpV";
                                allFlows = allFlows + "," + "ntpUpP";
                                wanFlows = wanFlows + "," + "ntpUpP";
                            } else if (ofFlow.getSrcPort().equals("53")) {
                                allFlows = allFlows + "," + "dnsDownV";
                                wanFlows = wanFlows + "," + "dnsDownV";
                                allFlows = allFlows + "," + "dnsDownP";
                                wanFlows = wanFlows + "," + "dnsDownP";
                            } else if (ofFlow.getDstPort().equals("53")) {
                                allFlows = allFlows + "," + "dnsUpV";
                                wanFlows = wanFlows + "," + "dnsUpV";
                                allFlows = allFlows + "," + "dnsUpP";
                                wanFlows = wanFlows + "," + "dnsUpP";
                            }
                        }
                        break;
                    case Constants.ETH_TYPE_ARP:
                        if (ofFlow.getSrcMac().equals("*")) {
                            allFlows = allFlows + "," + "arpDownV";
                            lanFlows = lanFlows + "," + "arpDownV";
                            allFlows = allFlows + "," + "arpDownP";
                            lanFlows = lanFlows + "," + "arpDownP";
                        } else {
                            allFlows = allFlows + "," + "arpUpV";
                            lanFlows = lanFlows + "," + "arpUpV";
                            allFlows = allFlows + "," + "arpUpP";
                            lanFlows = lanFlows + "," + "arpUpP";
                        }
                        break;
                }
            } else if (ofFlow.getPriority() >= 800 && ofFlow.getPriority() < 900 ) {
                if (ofFlow.getIpProto().equals(Constants.TCP_PROTO)) {
                    allFlows = allFlows + "," + "d2wTcp" + getPort(ofFlow.getDstPort()) + "UpV";
                    wanFlows = wanFlows + "," + "d2wTcp" + getPort(ofFlow.getDstPort()) + "UpV";
                    allFlows = allFlows + "," + "d2wTcp" + getPort(ofFlow.getDstPort()) + "UpP";
                    wanFlows = wanFlows + "," + "d2wTcp" + getPort(ofFlow.getDstPort()) + "UpP";
                } else {
                    allFlows = allFlows + "," + "d2wUdp" + getPort(ofFlow.getDstPort()) + "UpV";
                    wanFlows = wanFlows + "," + "d2wUdp" + getPort(ofFlow.getDstPort()) + "UpV";
                    allFlows = allFlows + "," + "d2wUdp" + getPort(ofFlow.getDstPort()) + "UpP";
                    wanFlows = wanFlows + "," + "d2wUdp" + getPort(ofFlow.getDstPort()) + "UpP";
                }
            } else if (ofFlow.getPriority() >= 700 && ofFlow.getPriority() < 800 ) {
                if (ofFlow.getIpProto().equals(Constants.TCP_PROTO)) {
                    allFlows = allFlows + "," + "w2dTcp" + getPort(ofFlow.getSrcPort()) + "DownV";
                    wanFlows = wanFlows + "," + "w2dTcp" + getPort(ofFlow.getSrcPort()) + "DownV";
                    allFlows = allFlows + "," + "w2dTcp" + getPort(ofFlow.getSrcPort()) + "DownP";
                    wanFlows = wanFlows + "," + "w2dTcp" + getPort(ofFlow.getSrcPort()) + "DownP";
                } else {
                    allFlows = allFlows + "," + "w2dUdp" + getPort(ofFlow.getSrcPort()) + "DownV";
                    wanFlows = wanFlows + "," + "w2dUdp" + getPort(ofFlow.getSrcPort()) + "DownV";
                    allFlows = allFlows + "," + "w2dUdp" + getPort(ofFlow.getSrcPort()) + "DownP";
                    wanFlows = wanFlows + "," + "w2dUdp" + getPort(ofFlow.getSrcPort()) + "DownP";
                }
            } else if (ofFlow.getPriority() >= 600 && ofFlow.getPriority() < 700 ) {
                if (ofFlow.getIpProto().equals(Constants.TCP_PROTO)) {
                    if (!ofFlow.getSrcPort().equals("*") && ofFlow.getDstPort().equals("*")) {
                        allFlows = allFlows + "," + "l2dTcp" + getPort(ofFlow.getSrcPort()) + "UpV";
                        lanFlows = lanFlows + "," + "l2dTcp" + getPort(ofFlow.getSrcPort()) + "UpV";
                        allFlows = allFlows + "," + "l2dTcp" + getPort(ofFlow.getSrcPort()) + "UpP";
                        lanFlows = lanFlows + "," + "l2dTcp" + getPort(ofFlow.getSrcPort()) + "UpP";
                    } else {
                        allFlows = allFlows + "," + "l2dTcp" + getPort(ofFlow.getDstPort()) + "DownV";
                        lanFlows = lanFlows + "," + "l2dTcp" + getPort(ofFlow.getDstPort()) + "DownV";
                        allFlows = allFlows + "," + "l2dTcp" + getPort(ofFlow.getDstPort()) + "DownP";
                        lanFlows = lanFlows + "," + "l2dTcp" + getPort(ofFlow.getDstPort()) + "DownP";
                    }

                } else if (ofFlow.getIpProto().equals(Constants.UDP_PROTO)){
                    if (!ofFlow.getSrcPort().equals("*") && ofFlow.getDstPort().equals("*")) {
                        allFlows = allFlows + "," + "l2dUdp" + getPort(ofFlow.getSrcPort()) + "UpV";
                        lanFlows = lanFlows + "," + "l2dUdp" + getPort(ofFlow.getSrcPort()) + "UpV";
                        allFlows = allFlows + "," + "l2dUdp" + getPort(ofFlow.getSrcPort()) + "UpP";
                        lanFlows = lanFlows + "," + "l2dUdp" + getPort(ofFlow.getSrcPort()) + "UpP";
                    } else {
                        allFlows = allFlows + "," + "l2dUdp" + getPort(ofFlow.getDstPort()) + "DownV";
                        lanFlows = lanFlows + "," + "l2dUdp" + getPort(ofFlow.getDstPort()) + "DownV";
                        allFlows = allFlows + "," + "l2dUdp" + getPort(ofFlow.getDstPort()) + "DownP";
                        lanFlows = lanFlows + "," + "l2dUdp" + getPort(ofFlow.getDstPort()) + "DownP";
                    }

                } else if (ofFlow.getIpProto().equals(Constants.ICMP_PROTO)){
                    if (!ofFlow.getSrcPort().equals("*") && ofFlow.getDstPort().equals("*")) {
                        allFlows = allFlows + "," + "l2dIcmp" + getPort(ofFlow.getSrcPort()) + "UpV";
                        lanFlows = lanFlows + "," + "l2dIcmp" + getPort(ofFlow.getSrcPort()) + "UpV";
                        allFlows = allFlows + "," + "l2dIcmp" + getPort(ofFlow.getSrcPort()) + "UpP";
                        lanFlows = lanFlows + "," + "l2dIcmp" + getPort(ofFlow.getSrcPort()) + "UpP";
                    } else {
                        allFlows = allFlows + "," + "l2dIcmp" + getPort(ofFlow.getDstPort()) + "DownV";
                        lanFlows = lanFlows + "," + "l2dIcmp" + getPort(ofFlow.getDstPort()) + "DownV";
                        allFlows = allFlows + "," + "l2dIcmp" + getPort(ofFlow.getDstPort()) + "DownP";
                        lanFlows = lanFlows + "," + "l2dIcmp" + getPort(ofFlow.getDstPort()) + "DownP";
                    }

                }
            }
        }
        PrintWriter flowWriter = new PrintWriter(flowIdfilename, "UTF-8");
        flowWriter.println(allFlows);
        flowWriter.println(lanFlows);
        flowWriter.println(wanFlows);
        flowWriter.close();
    }

//    private void printFlowIds() throws IOException {
//        String allFlows = "allFlows";
//        String lanFlows = "lanFlows";
//        String wanFlows = "wanFlows";
//        boolean first = true;
//        for (int i = 0; i < columns.size(); i++) {
//            OFFlow ofFlow = columns.get(i);
//            if (ofFlow.getPriority() == 1000) {
//                switch (ofFlow.getEthType()) {
//                    case Constants.ETH_TYPE_IPV4:
//                        if (Integer.parseInt(ofFlow.getIpProto()) == 1) {
//                            if (ofFlow.getSrcMac().equals(OFController.getInstance().getSwitch(dpId).getMacAddress())) {
//                                allFlows = allFlows + "," + "icmpDown";
//                                wanFlows = wanFlows + "," + "icmpDown";
//                                allFlows = allFlows + "," + "icmpDown";
//                                wanFlows = wanFlows + "," + "icmpDown";
//                            } else {
//                                allFlows = allFlows + "," + "icmpUp";
//                                wanFlows = wanFlows + "," + "icmpUp";
//                            }
//                        } else if (ofFlow.getIpProto().equals(Constants.UDP_PROTO)){
//                            if (ofFlow.getSrcPort().equals("123")) {
//                                allFlows = allFlows + "," + "ntpDown";
//                                wanFlows = wanFlows + "," + "ntpDown";
//                            } else if (ofFlow.getDstPort().equals("123")) {
//                                allFlows = allFlows + "," + "ntpUp";
//                                wanFlows = wanFlows + "," + "ntpUp";
//                            } else if (ofFlow.getSrcPort().equals("53")) {
//                                allFlows = allFlows + "," + "dnsDown";
//                                wanFlows = wanFlows + "," + "dnsDown";
//                            } else if (ofFlow.getDstPort().equals("53")) {
//                                allFlows = allFlows + "," + "dnsUp";
//                                wanFlows = wanFlows + "," + "dnsUp";
//                            }
//                        }
//                        break;
//                    case Constants.ETH_TYPE_ARP:
//                        if (ofFlow.getSrcMac().equals("*")) {
//                            allFlows = allFlows + "," + "arpDown";
//                            lanFlows = lanFlows + "," + "arpDown";
//                        } else {
//                            allFlows = allFlows + "," + "arpUp";
//                            lanFlows = lanFlows + "," + "arpUp";
//                        }
//                        break;
//                }
//            } else if (ofFlow.getPriority() >= 800 && ofFlow.getPriority() < 900 ) {
//                if (ofFlow.getIpProto().equals(Constants.TCP_PROTO)) {
//                    allFlows = allFlows + "," + "d2wTcp" + getPort(ofFlow.getDstPort()) + "Up";
//                    wanFlows = wanFlows + "," + "d2wTcp" + getPort(ofFlow.getDstPort()) + "Up";
//                } else {
//                    allFlows = allFlows + "," + "d2wUdp" + getPort(ofFlow.getDstPort()) + "Up";
//                    wanFlows = wanFlows + "," + "d2wUdp" + getPort(ofFlow.getDstPort()) + "Up";
//                }
//            } else if (ofFlow.getPriority() >= 700 && ofFlow.getPriority() < 800 ) {
//                if (ofFlow.getIpProto().equals(Constants.TCP_PROTO)) {
//                    allFlows = allFlows + "," + "w2dTcp" + getPort(ofFlow.getSrcPort()) + "Down";
//                    wanFlows = wanFlows + "," + "w2dTcp" + getPort(ofFlow.getSrcPort()) + "Down";
//                } else {
//                    allFlows = allFlows + "," + "w2dUdp" + getPort(ofFlow.getSrcPort()) + "Down";
//                    wanFlows = wanFlows + "," + "w2dUdp" + getPort(ofFlow.getSrcPort()) + "Down";
//                }
//            } else if (ofFlow.getPriority() >= 600 && ofFlow.getPriority() < 700 ) {
//                if (ofFlow.getIpProto().equals(Constants.TCP_PROTO)) {
//                    if (!ofFlow.getSrcPort().equals("*") && ofFlow.getDstPort().equals("*")) {
//                        allFlows = allFlows + "," + "l2dTcp" + getPort(ofFlow.getSrcPort()) + "Up";
//                        lanFlows = lanFlows + "," + "l2dTcp" + getPort(ofFlow.getSrcPort()) + "Up";
//                    } else {
//                        allFlows = allFlows + "," + "l2dTcp" + getPort(ofFlow.getDstPort()) + "Down";
//                        lanFlows = lanFlows + "," + "l2dTcp" + getPort(ofFlow.getDstPort()) + "Down";
//                    }
//
//                } else if (ofFlow.getIpProto().equals(Constants.UDP_PROTO)){
//                    if (!ofFlow.getSrcPort().equals("*") && ofFlow.getDstPort().equals("*")) {
//                        allFlows = allFlows + "," + "l2dUdp" + getPort(ofFlow.getSrcPort()) + "Up";
//                        lanFlows = lanFlows + "," + "l2dUdp" + getPort(ofFlow.getSrcPort()) + "Up";
//                    } else {
//                        allFlows = allFlows + "," + "l2dUdp" + getPort(ofFlow.getDstPort()) + "Down";
//                        lanFlows = lanFlows + "," + "l2dUdp" + getPort(ofFlow.getDstPort()) + "Down";
//                    }
//
//                } else if (ofFlow.getIpProto().equals(Constants.ICMP_PROTO)){
//                    if (!ofFlow.getSrcPort().equals("*") && ofFlow.getDstPort().equals("*")) {
//                        allFlows = allFlows + "," + "l2dIcmp" + getPort(ofFlow.getSrcPort()) + "Up";
//                        lanFlows = lanFlows + "," + "l2dIcmp" + getPort(ofFlow.getSrcPort()) + "Up";
//                    } else {
//                        allFlows = allFlows + "," + "l2dIcmp" + getPort(ofFlow.getDstPort()) + "Down";
//                        lanFlows = lanFlows + "," + "l2dIcmp" + getPort(ofFlow.getDstPort()) + "Down";
//                    }
//
//                }
//            }
//        }
//        PrintWriter flowWriter = new PrintWriter(flowIdfilename, "UTF-8");
//        flowWriter.println(allFlows);
//        flowWriter.println(lanFlows);
//        flowWriter.println(wanFlows);
//        flowWriter.close();
//    }

    private String getPort(String port) {
        if (port.equals("*")) {
            return "All";
        }
        return port;
    }

    private static void writeRaw(List<String> records) throws IOException {
        File file = new File(filename);
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

}
