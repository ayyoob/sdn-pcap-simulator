package com.ayyoob.sdn.of.simulator.apps.legacydevice;

import com.ayyoob.sdn.of.simulator.OFController;
import com.ayyoob.sdn.of.simulator.OFFlow;
import com.ayyoob.sdn.of.simulator.SimPacket;
import com.ayyoob.sdn.of.simulator.apps.StatListener;
import org.json.simple.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class LegacyDeviceStatsCollector implements StatListener {

    private boolean enabled = true;
    private boolean graphPrint = true;
    private long summerizationTimeInMillis = 60000;
    private List<OFFlow> columns = new ArrayList<>();
    private long lastLogTime = 0;
    private String dpId;
    private String deviceMac;
    private List<String> flowCounterdata = new ArrayList<>();
    private List<String> packetCounterdata = new ArrayList<>();
    private List<String> edgeCounterdata = new ArrayList<>();
    private List<String> graphData = new ArrayList<>();
    private String graphFileName;
    private String flowCounterfilename;
    private String packetCounterfilename;
    private String edgeCounterfilename;

    private static int graphCounter = 0;

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
        graphPrint = (Boolean) jsonObject.get("graphPrint");
        String filePostFix = (String) jsonObject.get("filePostFix");
        summerizationTimeInMillis = ((Long) jsonObject.get("summerizationTimeInSeconds")) * 1000;
        dpId = (String) jsonObject.get("dpId");
        deviceMac = (String) jsonObject.get("device");
        String currentPath = Paths.get(".").toAbsolutePath().normalize().toString();

        File workingDirectory = new File(currentPath + File.separator + "result");
        if (!workingDirectory.exists()) {
            workingDirectory.mkdir();
        }
        flowCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_flowCounter"+filePostFix+".csv";
        flowCounterdata.add("time,flowCount");
        packetCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_packetCounter"+filePostFix+".csv";
        packetCounterdata.add("time,packetCount");
        edgeCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_edgeCounter"+filePostFix+".csv";
        edgeCounterdata.add("time,packetCount");
        graphFileName = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_graph"+filePostFix+".txt";

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
            flowCounterdata.add(currentTime + "," + getDeviceFlowsSize());
            packetCounterdata.add(currentTime + "," + LegacyDeviceIdentifier.packetCounter);
            edgeCounterdata.add(currentTime + "," + LegacyDeviceIdentifier.deviceNode.getEdgeCount());
            LegacyDeviceIdentifier.packetCounter = 0;
            if (graphCounter == 15) {
                if (graphPrint) {
                    graphData.add("" + currentTime);
                    graphData.add(LegacyDeviceIdentifier.deviceNode.getNodeString());
                    graphData.add("\n\n ==========================================\n\n");
                    graphCounter = 0;
                }
            }
            graphCounter++;
        }

        if (flowCounterdata.size() > 2) {
            try {
                writePacketCountRaw(packetCounterdata);
                writeFlowCountRaw(flowCounterdata);
                writeEdgeCountRaw(edgeCounterdata);
                flowCounterdata.clear();
                packetCounterdata.clear();
                edgeCounterdata.clear();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        if (graphData.size() > 2) {
            try {
                writeGraph(graphData);
                graphData.clear();
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


    @Override
    public void complete() {
        if (!enabled) {
            return;
        }
        try {
            long currentTime = OFController.getInstance().getSwitch(dpId).getCurrentTime() + 1;
            lastLogTime = currentTime;
            flowCounterdata.add(currentTime + "," + getDeviceFlowsSize());
            packetCounterdata.add(currentTime + "," + LegacyDeviceIdentifier.packetCounter);
            edgeCounterdata.add(currentTime + "," + LegacyDeviceIdentifier.deviceNode.numberOFEdgeNode);
            LegacyDeviceIdentifier.packetCounter = 0;
            if (graphPrint) {
                graphData.add("" + currentTime);
                graphData.add(LegacyDeviceIdentifier.deviceNode.getNodeString());
                graphData.add("\n\n ==========================================\n\n");
                graphCounter = 0;
            }

            writeFlowCountRaw(flowCounterdata);
            if (graphPrint) {
                writeGraph(graphData);
            }
            writePacketCountRaw(packetCounterdata);
            writeEdgeCountRaw(edgeCounterdata);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeGraph(List<String> records) throws IOException {
        File file = new File(graphFileName);
        FileWriter writer = new FileWriter(file, true);
        //System.out.println("Writing graph raw... ");
        write(records, writer);

    }

    private void writeFlowCountRaw(List<String> records) throws IOException {
        File file = new File(flowCounterfilename);
        FileWriter writer = new FileWriter(file, true);
        //System.out.println("Writing raw... ");
        write(records, writer);

    }

    private void writePacketCountRaw(List<String> records) throws IOException {
        File file = new File(packetCounterfilename);
        FileWriter writer = new FileWriter(file, true);
       // System.out.println("Writing raw... ");
        write(records, writer);
    }

    private void writeEdgeCountRaw(List<String> records) throws IOException {
        File file = new File(edgeCounterfilename);
        FileWriter writer = new FileWriter(file, true);
        //System.out.println("Writing raw... ");
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
