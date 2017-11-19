package com.ayyoob.sdn.of.simulator.apps;

import com.ayyoob.sdn.of.simulator.OFController;
import com.ayyoob.sdn.of.simulator.OFFlow;
import com.ayyoob.sdn.of.simulator.SimPacket;
import com.ayyoob.sdn.of.simulator.Simulator;
import org.json.simple.JSONObject;

import java.io.*;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class SingleSwitchStatsCollector implements ControllerApp {
    int packetCount=0;

    private static boolean enabled = true;
    private static long summerizationTimeInMillis = 60000;
    private List<OFFlow> columns = new ArrayList<>();
    private long lastLogTime = 0;
    private String dpId;
    private List<String> data = new ArrayList<>();
    private static String filename;

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
    public void process(String dpId, SimPacket packet) {
        packetCount++;
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
                } else {
                    volumeData.append(0);
                }
                first =false;
            } else {
                if (detectedFlow != null) {
                    volumeData.append(",");
                    volumeData.append(detectedFlow.getVolumeTransmitted());
                } else {
                    volumeData.append(",");
                    volumeData.append(0);
                }
            }

        }
        return volumeData.toString();
    }

    @Override
    public void complete() {
        if (!enabled) {
            return;
        }
        try {
            writeRaw(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
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
