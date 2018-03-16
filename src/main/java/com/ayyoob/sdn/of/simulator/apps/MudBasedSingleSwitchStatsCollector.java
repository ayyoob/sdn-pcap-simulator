package com.ayyoob.sdn.of.simulator.apps;

import com.ayyoob.sdn.of.simulator.*;
import org.json.simple.JSONObject;

import java.io.*;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class MudBasedSingleSwitchStatsCollector implements StatListener {

    private static boolean enabled = true;
    private static long summerizationTimeInMillis = 60000;
    private List<OFFlow> columns = new ArrayList<>();
    private long lastLogTime = 0;
    private String dpId;
    private String deviceMac;
    private List<String> data = new ArrayList<>();
    private List<String> flowCounterdata = new ArrayList<>();
    private static String filename;
    private static String flowCounterfilename;

    private static final int D2G_FIXED_FLOW_PRIORITY = 850;
    private static final int D2G_PRIORITY = 800;
    private static final int G2D_FIXED_FLOW_PRIORITY = 750;
    private static final int G2D_PRIORITY = 700;
    private static final int L2D_FIXED_FLOW_PRIORITY = 650;
    private static final int L2D_PRIORITY = 600;
    private static final int DNS_FLOW_PRIORITY = 1100;
    private static List<Long> lastFlowPacketData = new ArrayList<>();

    @Override
    public void init(JSONObject jsonObject) {
        enabled = (Boolean) jsonObject.get("enabled");
        if (!enabled) {
            return;
        }
        String filePostFix = (String) jsonObject.get("filePostFix");
        summerizationTimeInMillis = ((Long) jsonObject.get("summerizationTimeInSeconds")) * 1000;
        dpId = (String) jsonObject.get("dpId");
        deviceMac = (String) jsonObject.get("device");
        String currentPath = Paths.get(".").toAbsolutePath().normalize().toString();

        File workingDirectory = new File(currentPath + File.separator + "result");
        if (!workingDirectory.exists()) {
            workingDirectory.mkdir();
        }
        filename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_flowstats"+filePostFix+".csv" ;
        flowCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_flowCounter"+filePostFix+".csv";

        data.add("time,externalG2D,externalD2G,arpup,arpdown,toDevice");
        flowCounterdata.add("time,flowCount");
        setupColumns();
    }

    @Override
    public void process(String dpId, SimPacket packet) {
        if (!enabled) {
            return;
        }
        if (!this.dpId.equals(dpId)) {
            return;
        }

        long nextLogTime = 0;
        if (lastLogTime == 0) {
            lastLogTime = packet.getTimestamp();
            return;
        }
        nextLogTime = lastLogTime + summerizationTimeInMillis;

        long currentTime = packet.getTimestamp();
        if (currentTime >= nextLogTime) {
            lastLogTime = currentTime;
            data.add(currentTime + "," + getVolumeData());
            flowCounterdata.add(currentTime + "," + getDeviceFlowsSize());
        }

        if (data.size() > 10000) {
            try {
                writeRaw(data);
                writeFlowCountRaw(flowCounterdata);
                flowCounterdata.clear();
                data.clear();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private int getDeviceFlowsSize() {
        int flowCount = 0;
        for (OFFlow ofFlow : OFController.getInstance().getAllFlows(dpId)) {
            if (!ofFlow.getSrcMac().equals(deviceMac) && !ofFlow.getDstMac().equals(deviceMac)) {
                continue;
            }
            flowCount++;
        }
        return flowCount;

    }

    private String getVolumeData() {
        boolean first = true;
        StringBuilder volumeData = new StringBuilder();
        volumeData.append("");
        String volumeLabel = "";
        List<OFFlow> flowStats = OFController.getInstance().getAllFlows(dpId);
        int indexC = 0;
        List<Long> currentFlowCountData = new ArrayList<>();
        for (OFFlow ofFlow : flowStats) {
            if (!ofFlow.getSrcMac().equals(deviceMac) && !ofFlow.getDstMac().equals(deviceMac)) {
                continue;
            }
            if (ofFlow.getPriority() == DNS_FLOW_PRIORITY || ofFlow.getPriority() == D2G_FIXED_FLOW_PRIORITY || ofFlow.getPriority() == G2D_FIXED_FLOW_PRIORITY||
                    ofFlow.getPriority() == L2D_FIXED_FLOW_PRIORITY || ofFlow.getPriority() == L2D_PRIORITY||
                    ofFlow.getPriority() == L2D_PRIORITY +20 ||
                    ofFlow.getPriority() == G2D_PRIORITY || ofFlow.getPriority() == D2G_PRIORITY) {
                if (first) {
                    if (lastFlowPacketData.size() == 0) {
                        volumeData.append(ofFlow.getPacketCount() +"," + ofFlow.getPacketCount());
                    } else {
                        volumeData.append(ofFlow.getPacketCount() +","+ (ofFlow.getPacketCount() - lastFlowPacketData.get(indexC)));
                    }
                    volumeLabel = ofFlow.getPriority() + ":" + ofFlow.getSrcPort() + ":" + ofFlow.getDstPort();
                    currentFlowCountData.add(ofFlow.getPacketCount());

                    first =false;
                } else {
                    volumeData.append(",");
                    if (lastFlowPacketData.size() == 0) {
                        volumeData.append(ofFlow.getPacketCount() +"," + ofFlow.getPacketCount());
                    } else {
                        volumeData.append(ofFlow.getPacketCount() +","+ (ofFlow.getPacketCount() - lastFlowPacketData.get(indexC)));
                    }
                    currentFlowCountData.add(ofFlow.getPacketCount());
                    volumeLabel = volumeLabel + "," + ofFlow.getPriority() + ":" + ofFlow.getSrcPort() + ":" + ofFlow.getDstPort();
                }
                indexC++;
            }
        }
        lastFlowPacketData.clear();
        lastFlowPacketData.addAll(currentFlowCountData);
        return volumeLabel + "," + volumeData.toString();
    }

    @Override
    public void complete() {
        if (!enabled) {
            return;
        }
        try {
            writeRaw(data);
            writeFlowCountRaw(flowCounterdata);
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

    private static void writeFlowCountRaw(List<String> records) throws IOException {
        File file = new File(flowCounterfilename);
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

    private void setupColumns() {
        OFFlow ofFlow = new OFFlow();
        ofFlow.setSrcMac(dpId);
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(G2D_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        columns.add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setDstMac(dpId);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(D2G_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
        OFController.getInstance().addFlow(dpId, ofFlow);
        columns.add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setSrcMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_ARP);
        ofFlow.setPriority(L2D_PRIORITY + 20);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        columns.add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_ARP);
        ofFlow.setPriority(L2D_PRIORITY + 20);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        columns.add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(L2D_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        columns.add(ofFlow);

        ofFlow = new OFFlow();
        ofFlow.setDstMac(deviceMac);
        ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
        ofFlow.setPriority(L2D_PRIORITY);
        ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
        columns.add(ofFlow);
    }

}
