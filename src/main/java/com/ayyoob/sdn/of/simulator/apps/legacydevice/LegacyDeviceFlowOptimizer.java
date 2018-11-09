package com.ayyoob.sdn.of.simulator.apps.legacydevice;

import com.ayyoob.sdn.of.simulator.Constants;
import com.ayyoob.sdn.of.simulator.OFController;
import com.ayyoob.sdn.of.simulator.OFFlow;
import com.ayyoob.sdn.of.simulator.SimPacket;
import com.ayyoob.sdn.of.simulator.apps.StatListener;
import com.ayyoob.sdn.of.simulator.processor.mud.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.javafx.geom.Edge;
import org.json.simple.JSONObject;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class LegacyDeviceFlowOptimizer implements StatListener {

    private boolean enabled = true;
    private long summerizationTimeInMillis = 60000;
    private List<OFFlow> columns = new ArrayList<>();
    private long lastLogTime = 0;
    private String dpId;
    private String deviceMac;
    private final String WILD_CARD= "*";
    private final String MUD_URN = "urn:ietf:params:mud";
    private DeviceNode allMUDNode;
    private static final int MAX_NODE = 500;
    private List<DeviceNode> identifiedDevices = new ArrayList<>();
    private String similarityCounterfilename;
    private String variationCounterfilename;
    private String jackardIndexfilename;
    private String jackardIndexLocalfilename;
    private String jackardIndexInternetfilename;
    private String similarityInternetCounterfilename;
    private String variationInternetCounterfilename;
    private String similarityLocalCounterfilename;
    private String variationLocalCounterfilename;
    private String similarityInternetEnpointCounterfilename;
    private String variationInternetEndpointCounterfilename;
    private String similarityLocalEndpointCounterfilename;
    private String variationLocalEndpointCounterfilename;

    private List<String> similarityCounterData = new ArrayList<>();
    private List<String> variationCounterData = new ArrayList<>();
    private List<String> jackardIndexData = new ArrayList<>();
    private List<String> jackardIndexLocalData = new ArrayList<>();
    private List<String> jackardIndexInternetData = new ArrayList<>();
    private List<String> similarityInternetCounterData = new ArrayList<>();
    private List<String> variationInternetCounterData = new ArrayList<>();
    private List<String> similarityLocalCounterData = new ArrayList<>();
    private List<String> variationLocalCounterData = new ArrayList<>();
    private List<String> similarityInternetEndpointCounterData = new ArrayList<>();
    private List<String> variationInternetEndpointCounterData = new ArrayList<>();
    private List<String> similarityLocalEndpointCounterData = new ArrayList<>();
    private List<String> variationLocalEndpointCounterData = new ArrayList<>();


    private String deviceVariationCounterfilename;
    private List<String> deviceVariationCounterData = new ArrayList<>();
    private List<String> alldeviceVariationCounterData = new ArrayList<>();
    private String deviceName ;
    private Map<String, List<String>> compareDevices = new HashMap<>();
    private String currentPath;
    private static LegacyDeviceFlowOptimizer instance;
    private static DeviceNode ssdpNode = new DeviceNode("ssdp");

    public LegacyDeviceFlowOptimizer getInstance() {
        return instance;
    }

    private List<Long> computationTimeList = new ArrayList<>();


    static {
        EdgeNode edgeNode = new EdgeNode();
        edgeNode.setEthType(2048);
        edgeNode.setIpProtocol(6);
        edgeNode.setDestPort(5000);
        ssdpNode.addNode(DeviceNode.Directions.TO_LOCAL, LegacyDeviceIdentifier.DEFAULT_GATEWAY_CONTROLLER, edgeNode);

        edgeNode = edgeNode.clone();
        edgeNode.setDestPort(49153);
        ssdpNode.addNode(DeviceNode.Directions.TO_LOCAL, "*", edgeNode);

        edgeNode = edgeNode.clone();
        edgeNode.setDestPort(49152);
        ssdpNode.addNode(DeviceNode.Directions.TO_LOCAL, "*", edgeNode);

        edgeNode = edgeNode.clone();
        edgeNode.setDestPort(8059);
        ssdpNode.addNode(DeviceNode.Directions.TO_LOCAL, "*", edgeNode);

        edgeNode = edgeNode.clone();
        edgeNode.setDestPort(49154);
        ssdpNode.addNode(DeviceNode.Directions.TO_LOCAL, "*", edgeNode);

        edgeNode = edgeNode.clone();
        edgeNode.setDestPort(8008);
        ssdpNode.addNode(DeviceNode.Directions.TO_LOCAL, "*", edgeNode);

        edgeNode = edgeNode.clone();
        edgeNode.setDestPort(80);
        ssdpNode.addNode(DeviceNode.Directions.TO_LOCAL, "*", edgeNode);


        edgeNode = new EdgeNode();
        edgeNode.setEthType(2048);
        edgeNode.setIpProtocol(6);
        edgeNode.setSourcePort(5000);
        ssdpNode.addNode(DeviceNode.Directions.FROM_LOCAL, LegacyDeviceIdentifier.DEFAULT_GATEWAY_CONTROLLER, edgeNode);


        edgeNode = edgeNode.clone();
        edgeNode.setSourcePort(49153);
        ssdpNode.addNode(DeviceNode.Directions.FROM_LOCAL, "*", edgeNode);

        edgeNode = edgeNode.clone();
        edgeNode.setSourcePort(49152);
        ssdpNode.addNode(DeviceNode.Directions.FROM_LOCAL, "*", edgeNode);

        edgeNode = edgeNode.clone();
        edgeNode.setSourcePort(8059);
        ssdpNode.addNode(DeviceNode.Directions.FROM_LOCAL, "*", edgeNode);

        edgeNode = edgeNode.clone();
        edgeNode.setSourcePort(49154);
        ssdpNode.addNode(DeviceNode.Directions.FROM_LOCAL, "*", edgeNode);

        edgeNode = edgeNode.clone();
        edgeNode.setSourcePort(8008);
        ssdpNode.addNode(DeviceNode.Directions.FROM_LOCAL, "*", edgeNode);

        edgeNode = edgeNode.clone();
        edgeNode.setSourcePort(80);
        ssdpNode.addNode(DeviceNode.Directions.FROM_LOCAL, "*", edgeNode);


    }

    @Override
    public void init(JSONObject jsonObject) {
        enabled = (Boolean) jsonObject.get("enabled");
        if (!enabled) {
            return;
        }
        summerizationTimeInMillis = ((Long) jsonObject.get("summerizationTimeInSeconds")) * 1000;
        dpId = (String) jsonObject.get("dpId");
        deviceMac = (String) jsonObject.get("device");
        deviceName = (String) jsonObject.get("deviceName");
        String val = (String) jsonObject.get("compareDevices");

        String profilePath = (String)jsonObject.get("profiles");

        currentPath = Paths.get(".").toAbsolutePath().normalize().toString();

        File workingDirectory = new File(currentPath + File.separator + "result");
        if (!workingDirectory.exists()) {
            workingDirectory.mkdir();
        }


        File file = new File(profilePath);
        if (file.exists()) {
            String[] files = file.list(new FilenameFilter() {
                @Override
                public boolean accept(File dir, String name) {
                    return name.endsWith(".json");
                }
            });
            allMUDNode = new DeviceNode("AllDevice");
            ArrayList<String> fileList = new ArrayList<>();
            for (String filex : files) {
                fileList.add(filex);
            }
            fileList.sort(String::compareToIgnoreCase);
            for (String profileName : fileList) {
                String filePath = file.getAbsolutePath() + File.separator + profileName;
                byte[] encoded = new byte[0];
                try {
                    encoded = Files.readAllBytes(Paths.get(filePath));
                    String mudPayload = new String(encoded, Charset.defaultCharset());
                    DeviceNode deviceNode = processMUD(profileName.replace(".json", ""), mudPayload);
                    deviceNode = removeRedundancies(deviceNode);
                    identifiedDevices.add(deviceNode);
                    for (DeviceNode.Directions direction : DeviceNode.Directions.values()) {
                        for (EndpointNode endpointNode : deviceNode.getEndpointNodes(direction)) {
                            for (EdgeNode edgeNode : endpointNode.getEdges()) {
                                if (allMUDNode.getAbsoluteMatchingEndpointNode(direction, endpointNode.getValue(), edgeNode) == null) {
                                    allMUDNode.addNode(direction, endpointNode.getValue(), edgeNode);
                                }
                            }
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
            //System.out.println(allMUDNode.getNodeString());
        } else {
            System.out.println("Invalid mud profile directory path");
        }
        String devieMeta = "";
        for (DeviceNode deviceNode : identifiedDevices) {
            if (deviceNode.getValue().equals(deviceName)) {
                System.out.println(deviceNode.getNodeString());
            }
            devieMeta = devieMeta + "," + deviceNode.getValue() ;
        }

        similarityCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_similarityCounter.csv";
        similarityCounterData.add("time" + devieMeta);
        variationCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_variationCounter.csv";
        variationCounterData.add("time" + devieMeta);
        jackardIndexfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_jackardIndex.csv";
        jackardIndexData.add("time" + devieMeta);

        similarityInternetCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_similarityInternetCounter.csv";
        similarityInternetCounterData.add("time" + devieMeta);
        variationInternetCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_variationInternetCounter.csv";
        variationInternetCounterData.add("time" + devieMeta);
        jackardIndexInternetfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_jackardIndexInternet.csv";
        jackardIndexInternetData.add("time" + devieMeta);

        similarityLocalCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_similarityLocalCounter.csv";
        similarityLocalCounterData.add("time" + devieMeta);
        variationLocalCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_variationLocalCounter.csv";
        variationLocalCounterData.add("time" + devieMeta);
        jackardIndexLocalfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_jackardIndexLocal.csv";
        jackardIndexLocalData.add("time" + devieMeta);

        similarityInternetEnpointCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_similarityInternetEndpointCounter.csv";
        similarityInternetEndpointCounterData.add("time" + devieMeta);
        variationInternetEndpointCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_variationInternetEncpointCounter.csv";
        variationInternetEndpointCounterData.add("time" + devieMeta);

        similarityLocalEndpointCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_similarityLocalEndpointCounter.csv";
        similarityLocalEndpointCounterData.add("time" + devieMeta);
        variationLocalEndpointCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_variationLocalEndpointCounter.csv";
        variationLocalEndpointCounterData.add("time" + devieMeta);

        deviceVariationCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_DirectionVariationCounter.csv";
        String header = "time,TISimilarity,TIVariation,TIEndpointSimilarity,TIEndpointVariation" +
                ",FISimilarity,FIVariation,FIEndpointSimilarity,FIEndpointVariation" +
                ",TLSimilarity,TLVariation,TLEndpointSimilarity,TLEndpointVariation" +
                ",FLSimilarity,FLVariation,FLEndpointSimilarity,FLEndpointVariation" +
                ",ISimilarity,IVariation,IEndpointSimilarity,IEndpointVariation" +
                ",LSimilarity,LVariation,LEndpointSimilarity,LEndpointVariation" +
                ",Similarity,Variation,EndpointSimilarity,EndpointVariation";
        deviceVariationCounterData.add(header);

        if (val.length() > 0) {
            String keys[] = val.split(",");
            for (String key : keys) {
                List<String> row = new ArrayList<>();
                row.add(header);
                compareDevices.put(key, row);
            }
        }

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
            //start computing

            long startTime = System.currentTimeMillis();
            optimizeDevice();
            String[] similarityInfo = calculateVariations();

            similarityCounterData.add(currentTime + similarityInfo[0]);
            variationCounterData.add(currentTime + similarityInfo[1]);
            jackardIndexData.add(currentTime + similarityInfo[2]);

            DeviceNode.Directions directions[] = {DeviceNode.Directions.FROM_INTERNET, DeviceNode.Directions.TO_INTERNET};
            similarityInfo = calculateLayerVariations(directions);
            similarityInternetCounterData.add(currentTime + similarityInfo[0]);
            variationInternetCounterData.add(currentTime + similarityInfo[1]);
            jackardIndexInternetData.add(currentTime + similarityInfo[2]);

            DeviceNode.Directions localdirections[] = {DeviceNode.Directions.TO_LOCAL, DeviceNode.Directions.FROM_LOCAL};
            similarityInfo = calculateLayerVariations(localdirections);
            similarityLocalCounterData.add(currentTime + similarityInfo[0]);
            variationLocalCounterData.add(currentTime + similarityInfo[1]);
            jackardIndexLocalData.add(currentTime + similarityInfo[2]);

            long computationTime = System.currentTimeMillis() - startTime;
            computationTimeList.add(computationTime);
            //end


            String perDevice = calculateVariations(deviceName);
            deviceVariationCounterData.add(currentTime + perDevice);

            similarityInfo = calculateLayerEndpointVariations(directions);
            similarityInternetEndpointCounterData.add(currentTime + similarityInfo[0]);
            variationInternetEndpointCounterData.add(currentTime + similarityInfo[1]);

            similarityInfo = calculateLayerEndpointVariations(localdirections);
            similarityLocalEndpointCounterData.add(currentTime + similarityInfo[0]);
            variationLocalEndpointCounterData.add(currentTime + similarityInfo[1]);

            for (String key : compareDevices.keySet()) {
                String perCompareDevice = calculateVariations(key);
                compareDevices.get(key).add(currentTime + perCompareDevice);
            }
        }

        if (similarityCounterData.size() > 2) {
            try {
                writeCountRaw(similarityCounterData, similarityCounterfilename);
                writeCountRaw(variationCounterData, variationCounterfilename);
                writeCountRaw(jackardIndexData, jackardIndexfilename);

                writeCountRaw(similarityInternetCounterData, similarityInternetCounterfilename);
                writeCountRaw(variationInternetCounterData, variationInternetCounterfilename);
                writeCountRaw(jackardIndexInternetData, jackardIndexInternetfilename);
                writeCountRaw(similarityLocalCounterData, similarityLocalCounterfilename);
                writeCountRaw(variationLocalCounterData, variationLocalCounterfilename);
                writeCountRaw(jackardIndexLocalData, jackardIndexLocalfilename);

                writeCountRaw(similarityInternetEndpointCounterData, similarityInternetEnpointCounterfilename);
                writeCountRaw(variationInternetEndpointCounterData, variationInternetEndpointCounterfilename);
                writeCountRaw(similarityLocalEndpointCounterData, similarityLocalEndpointCounterfilename);
                writeCountRaw(variationLocalEndpointCounterData, variationLocalEndpointCounterfilename);

                writeDeviceVariationCountRaw(deviceVariationCounterData);
                for (String key : compareDevices.keySet()) {
                    writeCompareDeviceVariationCountRaw(key, compareDevices.get(key));
                    compareDevices.get(key).clear();
                }
                similarityCounterData.clear();
                variationCounterData.clear();
                jackardIndexData.clear();
                similarityInternetCounterData.clear();
                variationInternetCounterData.clear();
                similarityLocalCounterData.clear();
                variationLocalCounterData.clear();
                jackardIndexInternetData.clear();
                jackardIndexLocalData.clear();
                similarityInternetEndpointCounterData.clear();
                variationInternetEndpointCounterData.clear();
                similarityLocalEndpointCounterData.clear();
                variationLocalEndpointCounterData.clear();

                deviceVariationCounterData.clear();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void optimizeDevice() {

        DeviceNode deviceNode = LegacyDeviceIdentifier.deviceNode;
        for (DeviceNode.Directions direction : DeviceNode.Directions.values()) {

            List<EndpointNode> endpointNodes = deviceNode.getEndpointNodes(direction);
            List<EndpointNode> endpointsTobeOptimized = new ArrayList<>();
            int notMatchingEndpointCount = 0;
            Map<EdgeNode, Integer> repeatingEdges = new HashMap<>();
            for (EndpointNode endpointNode: endpointNodes) {
                List<EdgeNode> mudEdges = allMUDNode.getEdgeNodes(direction, endpointNode.getValue());
                if (mudEdges == null) {
                    mudEdges = allMUDNode.getEdgeNodes(direction, endpointNode.getValue() + "/32");
                }

                if (mudEdges == null) {
                    notMatchingEndpointCount++;
                }
                if (endpointNode.getEdges().size() > endpointNode.getPreviousChecked()) {
                    if (mudEdges == null) {
                        List<EdgeNode> optimizeEdgeNode = new ArrayList<>();
                        for (EdgeNode nonMatchEdge : endpointNode.getEdges()) {
                            boolean matchFound = false;
                            for (EdgeNode inst : optimizeEdgeNode) {
                                if (inst.isMatching(nonMatchEdge)) {
                                    matchFound = true;
                                    break;
                                }
                            }
                            if (!matchFound) {
                                if (nonMatchEdge.getSourcePortStart() == nonMatchEdge.getSourcePortEnd()
                                        && nonMatchEdge.getDestPortStart() == nonMatchEdge.getDestPortEnd()) {

                                    if (nonMatchEdge.getSourcePortStart() < Constants.RESERVED_MIN_PORT) {
                                        nonMatchEdge.setDestPortStart(Constants.MIN_PORT);
                                        nonMatchEdge.setDestPortEnd(Constants.MAX_PORT);
                                        optimizeEdgeNode.add(nonMatchEdge);
                                    } else if (nonMatchEdge.getDestPortStart() < Constants.RESERVED_MIN_PORT) {
                                        nonMatchEdge.setSourcePortStart(Constants.MIN_PORT);
                                        nonMatchEdge.setSourcePortEnd(Constants.MAX_PORT);
                                        optimizeEdgeNode.add(nonMatchEdge);
                                    }  else {
                                        EdgeNode copyEdge = nonMatchEdge.clone();
                                        copyEdge.setSourcePortStart(Constants.RESERVED_MIN_PORT);
                                        copyEdge.setSourcePortEnd(Constants.MAX_PORT);
                                        nonMatchEdge.setDestPortStart(Constants.RESERVED_MIN_PORT);
                                        nonMatchEdge.setDestPortEnd(Constants.MAX_PORT);
                                        optimizeEdgeNode.add(copyEdge);
                                        optimizeEdgeNode.add(nonMatchEdge);
                                        if (repeatingEdges.get(copyEdge) == null) {
                                            repeatingEdges.put(copyEdge, 1);
                                        } else {
                                            repeatingEdges.put(copyEdge, repeatingEdges.get(copyEdge) + 1);
                                        }
                                    }
                                } else {
                                    optimizeEdgeNode.add(nonMatchEdge);
                                }
                                if (repeatingEdges.get(nonMatchEdge) == null) {
                                    repeatingEdges.put(nonMatchEdge, 1);
                                } else {
                                    repeatingEdges.put(nonMatchEdge, repeatingEdges.get(nonMatchEdge) + 1);
                                }
                            }
                        }
                        int udpFlows = 0;
                        for (EdgeNode edgeNode : optimizeEdgeNode) {
                            if (edgeNode.getIpProtocol() == 17) {
                                udpFlows++;
                            }
                        }

                        int newCount = (optimizeEdgeNode.size() - udpFlows);
//                        if (endpointNode.getTmpEdgeCount() == 0) {
//                            deviceNode.numberOFEdgeNode = deviceNode.numberOFEdgeNode - endpointNode.getEdges().size()
//                                    + newCount;
//                        } else {
//                            int duplicates = (endpointNode.getPreviousChecked()-endpointNode.getTmpEdgeCount());
//                            deviceNode.numberOFEdgeNode = deviceNode.numberOFEdgeNode + duplicates - endpointNode.getEdges().size()
//                                    + newCount;
//                        }
//                        endpointNode.setTmpEdgeCount(newCount);
                        endpointNode.setEdges(optimizeEdgeNode);

                    } else {
                        List<EdgeNode> deviceEdges =  endpointNode.getEdges();
                        List<EdgeNode> matchingEdge = new ArrayList<>();
                        List<EdgeNode> notMatchingEdge = new ArrayList<>();
                        for (EdgeNode devEdge : deviceEdges) {

                            boolean exisitingNode = false;
                            for (EdgeNode existingMatchEdge : matchingEdge) {
                                if (existingMatchEdge.isMatching(devEdge)) {
                                    exisitingNode = true;
                                    break;
                                }
                            }
                            if (exisitingNode) {
                                continue;
                            }
                            boolean matchingFound = false;
                            Set<EdgeNode> multipleEdge = new HashSet<>();
                            for (EdgeNode mudEdge : mudEdges) {
                                if (mudEdge.isMatching(devEdge)
                                        && !((mudEdge.getIpProtocol() == 17 || mudEdge.getIpProtocol() == 6)
                                        && mudEdge.getSourcePortStart() == Constants.MIN_PORT
                                        && mudEdge.getSourcePortEnd() == Constants.MAX_PORT
                                        && mudEdge.getDestPortStart() == Constants.MIN_PORT
                                        && mudEdge.getDestPortEnd() == Constants.MAX_PORT)) {
                                    multipleEdge.add(mudEdge);
                                    matchingFound = true;
                                }
                            }

                            if (!matchingFound) {
                                notMatchingEdge.add(devEdge);
                            } else if (multipleEdge.size() > 1) {

                                //find optimal edge
                                int sourcePortStart = Constants.MIN_PORT;
                                int sourcePortEnd = Constants.MAX_PORT;
                                int destPortStart = Constants.MIN_PORT;
                                int destPortEnd = Constants.MAX_PORT;
                                int protocol = -1;
                                for (EdgeNode mudEdge : multipleEdge) {
                                    if (mudEdge.getIpProtocol() > protocol) {
                                        protocol = mudEdge.getIpProtocol();
                                    }
                                    if (mudEdge.getSourcePortStart() > sourcePortStart) {
                                        sourcePortStart = mudEdge.getSourcePortStart();
                                    }
                                    if (mudEdge.getSourcePortEnd() < sourcePortEnd) {
                                        sourcePortEnd = mudEdge.getSourcePortEnd();
                                    }
                                    if (mudEdge.getDestPortStart() > destPortStart) {
                                        destPortStart = mudEdge.getDestPortStart();
                                    }
                                    if (mudEdge.getDestPortEnd() < destPortEnd) {
                                        destPortEnd = mudEdge.getDestPortEnd();
                                    }
                                }
                                if ((protocol == 17 || protocol == 6)
                                        && sourcePortStart == Constants.MIN_PORT
                                        && sourcePortEnd == Constants.MAX_PORT
                                        && destPortStart == Constants.MIN_PORT
                                        && destPortEnd == Constants.MAX_PORT) {
                                    notMatchingEdge.add(devEdge);
                                } else {
                                    devEdge.setSourcePortStart(sourcePortStart);
                                    devEdge.setSourcePortEnd(sourcePortEnd);
                                    devEdge.setDestPortStart(destPortStart);
                                    devEdge.setDestPortEnd(destPortEnd);
                                    matchingEdge.add(devEdge);
                                }
                            } else {
                                EdgeNode onlyMatch = (EdgeNode) multipleEdge.toArray()[0];

                                if ((onlyMatch.getIpProtocol() == 17 || onlyMatch.getIpProtocol() == 6)
                                        && onlyMatch.getSourcePortStart() == Constants.MIN_PORT
                                        && onlyMatch.getSourcePortEnd() == Constants.MAX_PORT
                                        && onlyMatch.getDestPortStart() == Constants.MIN_PORT
                                        && onlyMatch.getDestPortEnd() == Constants.MAX_PORT) {
                                    notMatchingEdge.add(devEdge);
                                } else {
                                    matchingEdge.add(onlyMatch);
                                }
                            }
                        }

                        // optimize notMatchihngEdge()
                        List<EdgeNode> optimizeEdgeNode = new ArrayList<>();
                        for (EdgeNode nonMatchEdge : notMatchingEdge) {
                            boolean matchFound = false;
                            for (EdgeNode inst : optimizeEdgeNode) {
                                if (inst.isMatching(nonMatchEdge)) {
                                    matchFound = true;
                                    break;
                                }
                            }
                            if (!matchFound) {
                                if (nonMatchEdge.getSourcePortStart() == nonMatchEdge.getSourcePortEnd()
                                        && nonMatchEdge.getDestPortStart() == nonMatchEdge.getDestPortEnd()) {
                                    EdgeNode ds = nonMatchEdge.clone();
                                    if (nonMatchEdge.getSourcePortStart() < Constants.RESERVED_MIN_PORT) {
                                        nonMatchEdge.setDestPortStart(Constants.MIN_PORT);
                                        nonMatchEdge.setDestPortEnd(Constants.MAX_PORT);

                                    } else if (nonMatchEdge.getDestPortStart() < Constants.RESERVED_MIN_PORT) {
                                        nonMatchEdge.setSourcePortStart(Constants.MIN_PORT);
                                        nonMatchEdge.setSourcePortEnd(Constants.MAX_PORT);

                                    }  else {
                                        EdgeNode copyEdge = nonMatchEdge.clone();
                                        copyEdge.setSourcePortStart(Constants.RESERVED_MIN_PORT);
                                        copyEdge.setSourcePortEnd(Constants.MAX_PORT);
                                        nonMatchEdge.setDestPortStart(Constants.RESERVED_MIN_PORT);
                                        nonMatchEdge.setDestPortEnd(Constants.MAX_PORT);
                                        optimizeEdgeNode.add(copyEdge);

                                    }
                                    optimizeEdgeNode.add(nonMatchEdge);
                                } else {
                                    optimizeEdgeNode.add(nonMatchEdge);
                                }
                            }
                        }

                        matchingEdge.addAll(optimizeEdgeNode);
//                        deviceNode.numberOFEdgeNode = deviceNode.numberOFEdgeNode - endpointNode.getEdges().size()
//                                + matchingEdge.size();
                        endpointNode.setEdges(matchingEdge);
                    }
                    endpointNode.setPreviousChecked(endpointNode.getEdges().size());
                } else {
                    if (mudEdges == null) {

                        List<EdgeNode> optimizeEdgeNode = new ArrayList<>();
                        for (EdgeNode nonMatchEdge : endpointNode.getEdges()) {
                            if (repeatingEdges.get(nonMatchEdge) == null) {
                                repeatingEdges.put(nonMatchEdge, 1);
                            } else {
                                repeatingEdges.put(nonMatchEdge, repeatingEdges.get(nonMatchEdge) + 1);
                            }
                        }
                    }
                }
            }
            //using rate limit to stop the tree growing.
            if (notMatchingEndpointCount > MAX_NODE) {
                List<EdgeNode> maxEdges = new ArrayList<>();
                for (EdgeNode edgeNode : repeatingEdges.keySet()) {
                    if (repeatingEdges.get(edgeNode) >  MAX_NODE) {
                        maxEdges.add(edgeNode.clone());
                    }
                }
                for (EdgeNode maxEdge : maxEdges) {
                    if (deviceNode.getMatchingEndpointNode(direction, "*", maxEdge) == null) {
                        deviceNode.addNode(direction, "*", maxEdge);
                    }
                }
            }
            // optimize endpoints
            if (endpointsTobeOptimized.size() > 0) {
                Set<EdgeNode> edges = new HashSet<>();
                for (EndpointNode endpointNode : endpointsTobeOptimized) {
                    edges.addAll(endpointNode.getEdges());
                    deviceNode.removeNode(direction, endpointNode.getValue());
                }
                List<EdgeNode> edgeList = new ArrayList<EdgeNode>();
                edgeList.addAll(edges);
                deviceNode.addNode(direction, "*", edgeList);
            }

        }
    }

    private String[] calculateVariations() {
        DeviceNode generatedNode = LegacyDeviceIdentifier.deviceNode;
        String[] values = new String[3];
        values[0] = "";
        values[1] = "";
        values[2] = "";

        for (DeviceNode existingDevice : identifiedDevices) {
            // A - device to be discovered.
            //B - identified device.
            DeviceNode deviceNode = findOptimalStructure(generatedNode, existingDevice);
            int numberOfARules = deviceNode.numberOFEdgeNode;
            int numberOfBRules = existingDevice.numberOFEdgeNode;
            int numberOfAIntersectionBRules = 0;
            for (DeviceNode.Directions direction : DeviceNode.Directions.values()) {
                List<EndpointNode> discoveredEndpoints = deviceNode.getEndpointNodes(direction);

                for (EndpointNode discoveredEndpoint : discoveredEndpoints) {
                    Set<EdgeNode> edgeNodeSet = new HashSet<>();
                    for (EdgeNode edgeNode : discoveredEndpoint.getEdges()) {
                        EndpointNode bEndpointNode = existingDevice.getMatchingEndpointNode(direction,
                                discoveredEndpoint.getValue(), edgeNode);
                        if (bEndpointNode != null && !edgeNodeSet.contains(bEndpointNode.getEdges().get(0))) {
                            numberOfAIntersectionBRules++;
                            edgeNodeSet.addAll(bEndpointNode.getEdges());
                        }
                    }
                }
            }
            double similarity = (numberOfAIntersectionBRules * 100.0)/numberOfBRules;
            double variation = ((numberOfARules - numberOfAIntersectionBRules) * 100.0)/numberOfARules;
            double jackardIndex = (numberOfAIntersectionBRules * 100.0)/(numberOfARules + numberOfBRules - numberOfAIntersectionBRules);
            values[0] = values[0]+ "," + round(similarity) ;
            values[1] = values[1] +  ","+ round(variation) ;
            values[2] = values[2] + ","+ round(jackardIndex) ;

        }
        return values;
    }



    private String[] calculateLayerVariations(DeviceNode.Directions directions[]) {

        DeviceNode generatedNode = LegacyDeviceIdentifier.deviceNode;
        String[] values = new String[3];
        values[0] = "";
        values[1] = "";
        values[2] = "";
        for (DeviceNode existingDevice : identifiedDevices) {

            DeviceNode deviceNode = findOptimalStructure(generatedNode, existingDevice);

            // A - device to be discovered.
            //B - identified device.
            int numberOfARulesLayerDirection = 0;
            int numberOfBRulesLayerDirection = 0;
            int numberOfAIntersectionBRulesLayerDirection = 0;

            for (DeviceNode.Directions direction : directions) {

                int numberOfARulesDirection = 0;
                int numberOfBRulesDirection = existingDevice.getDirectionEdgeCount(direction);
                int numberOfAIntersectionBRulesDirection = 0;

                List<EndpointNode> discoveredEndpoints = deviceNode.getEndpointNodes(direction);
                for (EndpointNode discoveredEndpoint : discoveredEndpoints) {
                    numberOfARulesDirection = numberOfARulesDirection + discoveredEndpoint.getEdges().size();

                    Set<EdgeNode> edgeNodeSet = new HashSet<>();
                    for (EdgeNode edgeNode : discoveredEndpoint.getEdges()) {
                        EndpointNode bEndpointNode = existingDevice.getMatchingEndpointNode(direction,
                                discoveredEndpoint.getValue(), edgeNode);
                        if (bEndpointNode != null && !edgeNodeSet.contains(bEndpointNode.getEdges().get(0))) {
                            numberOfAIntersectionBRulesDirection++;
                            edgeNodeSet.add(bEndpointNode.getEdges().get(0));

                        }
                    }
                }

                numberOfARulesLayerDirection += numberOfARulesDirection;
                numberOfBRulesLayerDirection += numberOfBRulesDirection;
                numberOfAIntersectionBRulesLayerDirection += numberOfAIntersectionBRulesDirection;
            }
            double similarity = (numberOfAIntersectionBRulesLayerDirection * 100.0)/numberOfBRulesLayerDirection;
            double variation = ((numberOfARulesLayerDirection - numberOfAIntersectionBRulesLayerDirection) * 100.0)/numberOfARulesLayerDirection;
            double jackardIndex = (numberOfAIntersectionBRulesLayerDirection * 100.0)/(numberOfARulesLayerDirection + numberOfBRulesLayerDirection - numberOfAIntersectionBRulesLayerDirection);

            values[0] = values[0]+ "," + round(similarity) ;
            values[1] = values[1] +  ","+ round(variation) ;
            values[2] = values[2] +  ","+ round(jackardIndex) ;
        }
        return values;

    }

    private String[] calculateLayerEndpointVariations(DeviceNode.Directions directions[]) {

        DeviceNode generatedNode = LegacyDeviceIdentifier.deviceNode;
        String[] values = new String[2];
        values[0] = "";
        values[1] = "";
        for (DeviceNode existingDevice : identifiedDevices) {
            DeviceNode deviceNode = findOptimalStructure(generatedNode, existingDevice);
            // A - device to be discovered.
            //B - identified device.
            int numberOfAEndpointLayerDirection = 0;
            int numberOfBEndpointLayerDirection = 0;
            int numberOfAIntersectionBLayerEndpointDirection = 0;

            for (DeviceNode.Directions direction : directions) {

                List<EndpointNode> discoveredEndpoints = deviceNode.getEndpointNodes(direction);
                int numberOfAEndpointDirection = discoveredEndpoints.size();
                int numberOfBEndpointDirection = existingDevice.getEndpointNodes(direction).size();
                int numberOfAIntersectionBEndpointDirection = 0;

                for (EndpointNode discoveredEndpoint : discoveredEndpoints) {

                    if (existingDevice.isEndpointNodeExist(direction, discoveredEndpoint.getValue())) {
                        numberOfAIntersectionBEndpointDirection++;
                    }
                }

                numberOfAEndpointLayerDirection += numberOfAEndpointDirection;
                numberOfBEndpointLayerDirection += numberOfBEndpointDirection;
                numberOfAIntersectionBLayerEndpointDirection += numberOfAIntersectionBEndpointDirection;
            }
            double similarity = (numberOfAIntersectionBLayerEndpointDirection * 100.0)/numberOfBEndpointLayerDirection;
            double variation = ((numberOfAEndpointLayerDirection - numberOfAIntersectionBLayerEndpointDirection) * 100.0)/numberOfAEndpointLayerDirection;
            values[0] = values[0]+ "," + round(similarity) ;
            values[1] = values[1] +  ","+ round(variation) ;
        }
        return values;

    }


    private String calculateVariations(String deviceName) {
        String variations = "";
        DeviceNode generatedNode = LegacyDeviceIdentifier.deviceNode;
        DeviceNode referedDevice = null;

        for (DeviceNode existingDevice : identifiedDevices) {
            if (existingDevice.getValue().equals(deviceName)) {
                referedDevice = existingDevice;

                break;
            }
        }
        if (referedDevice != null) {
            DeviceNode deviceNode = findOptimalStructure(generatedNode, referedDevice);
            int numberOfARules = deviceNode.numberOFEdgeNode;
            int numberOfBRules = referedDevice.numberOFEdgeNode;
            int numberOfAIntersectionBRules = 0;

            int numberOFAEndpoints = 0;
            int numberOFBEndpoints = 0;
            int numberOfAIntersectionBEndpoints = 0;

            int numberOfARulesInternetDirection = 0;
            int numberOfBRulesInternetDirection = 0;
            int numberOfAIntersectionBRulesInternetDirection = 0;

            int numberOfAEndpointInternetDirection = 0;
            int numberOfBEndpointInternetDirection = 0;
            int numberOfAIntersectionBInternetEndpointDirection = 0;

            int numberOfARulesLocalDirection = 0;
            int numberOfBRulesLocalDirection = 0;
            int numberOfAIntersectionBRulesLocalDirection = 0;

            int numberOfAEndpointLocalDirection = 0;
            int numberOfBEndpointLocalDirection = 0;
            int numberOfAIntersectionBLocalEndpointDirection = 0;

            for (DeviceNode.Directions direction : DeviceNode.Directions.values()) {
                int numberOfARulesDirection = 0;
                int numberOfBRulesDirection = referedDevice.getDirectionEdgeCount(direction);
                int numberOfAIntersectionBRulesDirection = 0;

                List<EndpointNode> discoveredEndpoints = deviceNode.getEndpointNodes(direction);

                int numberOfAEndpointDirection = discoveredEndpoints.size();
                int numberOfBEndpointDirection = referedDevice.getEndpointNodes(direction).size();
                int numberOfAIntersectionBEndpointDirection = 0;

                numberOFAEndpoints = numberOFAEndpoints + discoveredEndpoints.size();
                numberOFBEndpoints = numberOFBEndpoints + referedDevice.getEndpointNodes(direction).size();
                for (EndpointNode discoveredEndpoint : discoveredEndpoints) {
                    numberOfARulesDirection = numberOfARulesDirection + discoveredEndpoint.getEdges().size();
                    if (referedDevice.isEndpointNodeExist(direction, discoveredEndpoint.getValue())) {
                        numberOfAIntersectionBEndpoints++;
                        numberOfAIntersectionBEndpointDirection++;
                    }
                    Set<EdgeNode> edgeNodeSet = new HashSet<>();
                    for (EdgeNode edgeNode : discoveredEndpoint.getEdges()) {
                        EndpointNode bEndpointNode = referedDevice.getMatchingEndpointNode(direction,
                                discoveredEndpoint.getValue(), edgeNode);
                        if (bEndpointNode != null && !edgeNodeSet.contains(bEndpointNode.getEdges().get(0))) {
                            numberOfAIntersectionBRulesDirection++;
                            numberOfAIntersectionBRules++;
                            edgeNodeSet.add(bEndpointNode.getEdges().get(0));

                        }
                    }
                }
                double similarityDirection = (numberOfAIntersectionBRulesDirection * 100.0) / numberOfBRulesDirection;
                double variationDirection = ((numberOfARulesDirection - numberOfAIntersectionBRulesDirection) * 100.0) / numberOfARulesDirection;
                double similarityEndpointDirection = (numberOfAIntersectionBEndpointDirection * 100.0) / numberOfBEndpointDirection;
                double variationEndpointDirection = ((numberOfAEndpointDirection - numberOfAIntersectionBEndpointDirection) * 100.0) / numberOfAEndpointDirection;

                variations = variations + "," + round(similarityDirection) + "," + round(variationDirection) + ","
                        + round(similarityEndpointDirection) + "," + round(variationEndpointDirection);

                if (direction == DeviceNode.Directions.TO_INTERNET || direction == DeviceNode.Directions.FROM_INTERNET) {
                    numberOfARulesInternetDirection += numberOfARulesDirection;
                    numberOfBRulesInternetDirection += numberOfBRulesDirection;
                    numberOfAIntersectionBRulesInternetDirection += numberOfAIntersectionBRulesDirection;

                    numberOfAEndpointInternetDirection += numberOfAEndpointDirection;
                    numberOfBEndpointInternetDirection += numberOfBEndpointDirection;
                    numberOfAIntersectionBInternetEndpointDirection += numberOfAIntersectionBEndpointDirection;
                } else {
                    numberOfARulesLocalDirection += numberOfARulesDirection;
                    numberOfBRulesLocalDirection += numberOfBRulesDirection;
                    numberOfAIntersectionBRulesLocalDirection += numberOfAIntersectionBRulesDirection;

                    numberOfAEndpointLocalDirection += numberOfAEndpointDirection;
                    numberOfBEndpointLocalDirection += numberOfBEndpointDirection;
                    numberOfAIntersectionBLocalEndpointDirection += numberOfAIntersectionBEndpointDirection;
                }

            }
            //Internet
            double similarity = (numberOfAIntersectionBRulesInternetDirection * 100.0) / numberOfBRulesInternetDirection;
            double variation = ((numberOfARulesInternetDirection - numberOfAIntersectionBRulesInternetDirection) * 100.0) / numberOfARulesInternetDirection;

            double similarityEndpoint = (numberOfAIntersectionBInternetEndpointDirection * 100.0) / numberOfBEndpointInternetDirection;
            double variationEndpoint = ((numberOfAEndpointInternetDirection - numberOfAIntersectionBInternetEndpointDirection) * 100.0) / numberOfAEndpointInternetDirection;

            variations = variations + "," + round(similarity) + "," + round(variation) + "," + round(similarityEndpoint)
                    + "," + round(variationEndpoint);
            // Local

            similarity = (numberOfAIntersectionBRulesLocalDirection * 100.0) / numberOfBRulesLocalDirection;
            variation = ((numberOfARulesLocalDirection - numberOfAIntersectionBRulesLocalDirection) * 100.0) / numberOfARulesLocalDirection;

            similarityEndpoint = (numberOfAIntersectionBLocalEndpointDirection * 100.0) / numberOfBEndpointLocalDirection;
            variationEndpoint = ((numberOfAEndpointLocalDirection - numberOfAIntersectionBLocalEndpointDirection) * 100.0) / numberOfAEndpointLocalDirection;

            variations = variations + "," + round(similarity) + "," + round(variation) + "," + round(similarityEndpoint)
                    + "," + round(variationEndpoint);

            //All
            similarity = (numberOfAIntersectionBRules * 100.0) / numberOfBRules;
            variation = ((numberOfARules - numberOfAIntersectionBRules) * 100.0) / numberOfARules;

            similarityEndpoint = (numberOfAIntersectionBEndpoints * 100.0) / numberOFBEndpoints;
            variationEndpoint = ((numberOFAEndpoints - numberOfAIntersectionBEndpoints) * 100.0) / numberOFAEndpoints;

            variations = variations + "," + round(similarity) + "," + round(variation) + "," + round(similarityEndpoint)
                    + "," + round(variationEndpoint);
        }


        return variations;

    }




    @Override
    public void complete() {
        if (!enabled) {
            return;
        }
        long currentTime = OFController.getInstance().getSwitch(dpId).getCurrentTime() + 1;

        //start computing
        long startTime = System.currentTimeMillis();
        optimizeDevice();
        String[] similarityInfo = calculateVariations();
        similarityCounterData.add(currentTime + similarityInfo[0]);
        variationCounterData.add(currentTime + similarityInfo[1]);
        jackardIndexData.add(currentTime + similarityInfo[2]);


        DeviceNode.Directions directions[] = {DeviceNode.Directions.FROM_INTERNET, DeviceNode.Directions.TO_INTERNET};
        similarityInfo = calculateLayerVariations(directions);
        similarityInternetCounterData.add(currentTime + similarityInfo[0]);
        variationInternetCounterData.add(currentTime + similarityInfo[1]);
        jackardIndexInternetData.add(currentTime + similarityInfo[2]);

        DeviceNode.Directions localdirections[] = {DeviceNode.Directions.TO_LOCAL, DeviceNode.Directions.FROM_LOCAL};
        similarityInfo = calculateLayerVariations(localdirections);
        similarityLocalCounterData.add(currentTime + similarityInfo[0]);
        variationLocalCounterData.add(currentTime + similarityInfo[1]);
        jackardIndexLocalData.add(currentTime + similarityInfo[2]);
        long computationTime = System.currentTimeMillis() - startTime;
        computationTimeList.add(computationTime);
        //end computing


        String perDevice = calculateVariations(deviceName);
        deviceVariationCounterData.add(currentTime + perDevice);

        similarityInfo = calculateLayerEndpointVariations(directions);
        similarityInternetEndpointCounterData.add(currentTime + similarityInfo[0]);
        variationInternetEndpointCounterData.add(currentTime + similarityInfo[1]);


        similarityInfo = calculateLayerEndpointVariations(localdirections);
        similarityLocalEndpointCounterData.add(currentTime + similarityInfo[0]);
        variationLocalEndpointCounterData.add(currentTime + similarityInfo[1]);

        for (String key : compareDevices.keySet()) {
            String perCompareDevice = calculateVariations(key);
            compareDevices.get(key).add(currentTime + perCompareDevice);
        }

        try {
            writeCountRaw(similarityCounterData, similarityCounterfilename);
            writeCountRaw(variationCounterData, variationCounterfilename);
            writeCountRaw(jackardIndexData, jackardIndexfilename);

            writeCountRaw(similarityInternetCounterData, similarityInternetCounterfilename);
            writeCountRaw(variationInternetCounterData, variationInternetCounterfilename);
            writeCountRaw(jackardIndexInternetData, jackardIndexInternetfilename);

            writeCountRaw(similarityLocalCounterData, similarityLocalCounterfilename);
            writeCountRaw(variationLocalCounterData, variationLocalCounterfilename);
            writeCountRaw(jackardIndexLocalData, jackardIndexLocalfilename);

            writeCountRaw(similarityInternetEndpointCounterData, similarityInternetEnpointCounterfilename);
            writeCountRaw(variationInternetEndpointCounterData, variationInternetEndpointCounterfilename);
            writeCountRaw(similarityLocalEndpointCounterData, similarityLocalEndpointCounterfilename);
            writeCountRaw(variationLocalEndpointCounterData, variationLocalEndpointCounterfilename);
            writeDeviceVariationCountRaw(deviceVariationCounterData);
            for (String key : compareDevices.keySet()) {
                writeCompareDeviceVariationCountRaw(key, compareDevices.get(key));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        DeviceNode referedDevice = null;

        for (DeviceNode existingDevice : identifiedDevices) {
            if (existingDevice.getValue().equals(deviceName)) {
                referedDevice = existingDevice;

                break;
            }
        }

        DeviceNode newNode = findOptimalStructure(LegacyDeviceIdentifier.deviceNode, referedDevice);
        newNode = difference(newNode, referedDevice);

        System.out.println(LegacyDeviceIdentifier.deviceNode.getNodeString());
        System.out.println("********************\n\n");
        System.out.println(newNode.getNodeString());
        System.out.println("***********END*********\n\n");

        //write averagee computation Time to file
        try {
            String pathT = currentPath + File.separator + "result" + File.separator
                    + "computationTime" + File.separator + "computationTime.csv";
            PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(pathT, true)));
            out.println(deviceName + "," + computationTimeList.stream().mapToDouble(val -> val).average().orElse(0.0));
            out.close();
        } catch (IOException e) {
            //exception handling left as an exercise for the reader
        }

    }

    private DeviceNode processMUD(String deviceName, String mudPayload) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        MudSpec mudSpec = mapper.readValue(mudPayload, MudSpec.class);
        DeviceNode deviceNode = loadMudSpec(deviceName, mudSpec);
        return deviceNode;
        //System.out.println(deviceNode.getNodeString());
    }

    private DeviceNode loadMudSpec(String deviceName, MudSpec mudSpec) {
        DeviceNode deviceNode = new DeviceNode(deviceName);
        List<String> fromDevicePolicyNames = new ArrayList<>();
        List<String> toDevicePolicyNames = new ArrayList<>();
        for (AccessDTO accessDTO : mudSpec.getIetfMud().getFromDevicePolicy().getAccessList().getAccessDTOList()) {
            fromDevicePolicyNames.add(accessDTO.getName());
        }

        for (AccessDTO accessDTO : mudSpec.getIetfMud().getToDevicePolicy().getAccessList().getAccessDTOList()) {
            toDevicePolicyNames.add(accessDTO.getName());
        }
        for (AccessControlListHolder accessControlListHolder : mudSpec.getAccessControlList().getAccessControlListHolder()) {
            if (fromDevicePolicyNames.contains(accessControlListHolder.getName())) {
                // FROM DEVICE
                for (Ace ace : accessControlListHolder.getAces().getAceList()) {
                    Match match = ace.getMatches();

                    //filter local
                    // FROM DEVICE TO LOCAL
                    if (match.getIetfMudMatch() != null && (match.getIetfMudMatch().getController() != null
                            || match.getIetfMudMatch().getLocalNetworks() != null)) {

                        EdgeNode edgeNode = new EdgeNode();
                        String endpoint = WILD_CARD;
                        //install local network related rules here

                        String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
                                .getEtherType();
                        edgeNode.setEthType(Integer.parseInt(etherType.substring(2), 16));
                        if (match.getIpv4Match() != null &&
                                match.getIpv4Match().getProtocol() != 0) {
                            edgeNode.setEthType(Integer.parseInt(Constants.ETH_TYPE_IPV4.substring(2), 16));
                            edgeNode.setIpProtocol(match.getIpv4Match().getProtocol());
                        }

                        if (match.getIpv6Match() != null) {
                            edgeNode.setEthType(Integer.parseInt(Constants.ETH_TYPE_IPV6.substring(2), 16));
                            edgeNode.setIpProtocol(match.getIpv6Match().getProtocol());
                        }

                        if (match.getEthMatch() != null) {
                            if (match.getEthMatch().getEtherType() != null) {
                                edgeNode.setEthType(Integer.parseInt(match.getEthMatch().getEtherType().substring(2), 16));
                            }
                            if (match.getEthMatch().getDstMacAddress() != null) {
                                endpoint = match.getEthMatch().getDstMacAddress();
                            }

                        }
                        //tcp
                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getDestinationPortMatch() != null) {
                            if (match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                                edgeNode.setDestPort(match.getTcpMatch().getDestinationPortMatch().getPort());
                            } else if (match.getTcpMatch().getDestinationPortMatch().getLowerPort() != 0
                                    && match.getTcpMatch().getDestinationPortMatch().getUpperPort() != 0) {
                                edgeNode.setDestPortStart(match.getTcpMatch().getDestinationPortMatch().getLowerPort());
                                edgeNode.setDestPortEnd(match.getTcpMatch().getDestinationPortMatch().getUpperPort());
                            }
                        }

                        if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null) {
                            if (match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                                edgeNode.setSourcePort(match.getTcpMatch().getSourcePortMatch().getPort());
                            } else if (match.getTcpMatch().getSourcePortMatch().getLowerPort() != 0
                                    && match.getTcpMatch().getSourcePortMatch().getUpperPort() != 0) {
                                edgeNode.setSourcePortStart(match.getTcpMatch().getSourcePortMatch().getLowerPort());
                                edgeNode.setSourcePortEnd(match.getTcpMatch().getSourcePortMatch().getUpperPort());
                            }
                        }
                        //udp
                        if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null) {
                            if (match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                                edgeNode.setDestPort(match.getUdpMatch().getDestinationPortMatch().getPort());
                            } else if (match.getUdpMatch().getDestinationPortMatch().getLowerPort() != 0
                                    && match.getUdpMatch().getDestinationPortMatch().getUpperPort() != 0) {
                                edgeNode.setDestPortStart(match.getUdpMatch().getDestinationPortMatch().getLowerPort());
                                edgeNode.setDestPortEnd(match.getUdpMatch().getDestinationPortMatch().getUpperPort());
                            }
                        }

                        if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null) {
                            if (match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                                edgeNode.setSourcePort(match.getUdpMatch().getSourcePortMatch().getPort());
                            } else if (match.getUdpMatch().getSourcePortMatch().getLowerPort() != 0
                                    && match.getUdpMatch().getSourcePortMatch().getUpperPort() != 0) {
                                edgeNode.setSourcePortStart(match.getUdpMatch().getSourcePortMatch().getLowerPort());
                                edgeNode.setSourcePortEnd(match.getUdpMatch().getSourcePortMatch().getUpperPort());
                            }
                        }

                        if ((match.getIpv4Match() != null && match.getIpv4Match().getDestinationIp() != null)) {
                            endpoint = match.getIpv4Match().getDestinationIp();
                        } else if (match.getIpv6Match() != null && match.getIpv6Match().getDestinationIp() != null) {
                            endpoint = match.getIpv6Match().getDestinationIp();
                        } else if (match.getIetfMudMatch().getController() != null &&
                                (match.getIetfMudMatch().getController().contains(MUD_URN))) {
                            endpoint = match.getIetfMudMatch().getController();
                        }
                        deviceNode.addNode(DeviceNode.Directions.TO_LOCAL, endpoint.replace("/32",""), edgeNode);

                    } else {
                        // TO INTERNET

                        EdgeNode edgeNode = new EdgeNode();
                        String endpoint = WILD_CARD;

                        String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
                                .getEtherType();
                        edgeNode.setEthType(Integer.parseInt(etherType.substring(2), 16));

                        if (match.getIpv4Match() != null &&
                                match.getIpv4Match().getProtocol() != 0) {
                            edgeNode.setEthType(Integer.parseInt(Constants.ETH_TYPE_IPV4.substring(2), 16));
                            edgeNode.setIpProtocol(match.getIpv4Match().getProtocol());
                        }

                        if (match.getIpv6Match() != null) {
                            edgeNode.setEthType(Integer.parseInt(Constants.ETH_TYPE_IPV6.substring(2), 16));
                            edgeNode.setIpProtocol(match.getIpv6Match().getProtocol());
                        }

                        //tcp
                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getDestinationPortMatch() != null) {
                            if (match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                                edgeNode.setDestPort(match.getTcpMatch().getDestinationPortMatch().getPort());
                            } else if (match.getTcpMatch().getDestinationPortMatch().getLowerPort() != 0
                                    && match.getTcpMatch().getDestinationPortMatch().getUpperPort() != 0) {
                                edgeNode.setDestPortStart(match.getTcpMatch().getDestinationPortMatch().getLowerPort());
                                edgeNode.setDestPortEnd(match.getTcpMatch().getDestinationPortMatch().getUpperPort());
                            }
                        }

                        if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null) {
                            if (match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                                edgeNode.setSourcePort(match.getTcpMatch().getSourcePortMatch().getPort());
                            } else if (match.getTcpMatch().getSourcePortMatch().getLowerPort() != 0
                                    && match.getTcpMatch().getSourcePortMatch().getUpperPort() != 0) {
                                edgeNode.setSourcePortStart(match.getTcpMatch().getSourcePortMatch().getLowerPort());
                                edgeNode.setSourcePortEnd(match.getTcpMatch().getSourcePortMatch().getUpperPort());
                            }
                        }
                        //udp
                        if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null) {
                            if (match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                                edgeNode.setDestPort(match.getUdpMatch().getDestinationPortMatch().getPort());
                            } else if (match.getUdpMatch().getDestinationPortMatch().getLowerPort() != 0
                                    && match.getUdpMatch().getDestinationPortMatch().getUpperPort() != 0) {
                                edgeNode.setDestPortStart(match.getUdpMatch().getDestinationPortMatch().getLowerPort());
                                edgeNode.setDestPortEnd(match.getUdpMatch().getDestinationPortMatch().getUpperPort());
                            }
                        }

                        if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null) {
                            if (match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                                edgeNode.setSourcePort(match.getUdpMatch().getSourcePortMatch().getPort());
                            } else if (match.getUdpMatch().getSourcePortMatch().getLowerPort() != 0
                                    && match.getUdpMatch().getSourcePortMatch().getUpperPort() != 0) {
                                edgeNode.setSourcePortStart(match.getUdpMatch().getSourcePortMatch().getLowerPort());
                                edgeNode.setSourcePortEnd(match.getUdpMatch().getSourcePortMatch().getUpperPort());
                            }
                        }

                        if (match.getIpv4Match() != null && match.getIpv4Match().getDestinationIp() != null) {
                            endpoint = match.getIpv4Match().getDestinationIp();
                        } else if (match.getIpv4Match() != null && match.getIpv4Match().getDstDnsName() != null) {
                            endpoint = match.getIpv4Match().getDstDnsName();
                        } else if (match.getIpv6Match() != null &&
                                match.getIpv6Match().getDestinationIp() != null) {
                            endpoint = match.getIpv6Match().getDestinationIp();
                        } else if (match.getIpv6Match() != null &&
                                match.getIpv6Match().getDstDnsName() != null) {
                            endpoint = match.getIpv6Match().getDstDnsName();
                        }

                        deviceNode.addNode(DeviceNode.Directions.TO_INTERNET, endpoint.replace("/32",""), edgeNode);

                    }
                }
            } else if (toDevicePolicyNames.contains(accessControlListHolder.getName())) {
                // TO DEVICE
                for (Ace ace : accessControlListHolder.getAces().getAceList()) {
                    Match match = ace.getMatches();

                    //filter local
                    // FROM LOCAL
                    if (match.getIetfMudMatch() != null && (match.getIetfMudMatch().getController() != null
                            || match.getIetfMudMatch().getLocalNetworks() != null)) {
                        //install local network related rules here
                        EdgeNode edgeNode = new EdgeNode();
                        String endpoint = WILD_CARD;

                        if (match.getIpv4Match() != null &&
                                match.getIpv4Match().getProtocol() != 0) {
                            edgeNode.setEthType(Integer.parseInt(Constants.ETH_TYPE_IPV4.substring(2), 16));
                            edgeNode.setIpProtocol(match.getIpv4Match().getProtocol());
                        }

                        if (match.getIpv6Match() != null) {
                            edgeNode.setEthType(Integer.parseInt(Constants.ETH_TYPE_IPV6.substring(2), 16));
                            edgeNode.setIpProtocol(match.getIpv6Match().getProtocol());
                        }

                        //tcp
                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getDestinationPortMatch() != null) {
                            if (match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                                edgeNode.setDestPort(match.getTcpMatch().getDestinationPortMatch().getPort());
                            } else if (match.getTcpMatch().getDestinationPortMatch().getLowerPort() != 0
                                    && match.getTcpMatch().getDestinationPortMatch().getUpperPort() != 0) {
                                edgeNode.setDestPortStart(match.getTcpMatch().getDestinationPortMatch().getLowerPort());
                                edgeNode.setDestPortEnd(match.getTcpMatch().getDestinationPortMatch().getUpperPort());
                            }
                        }

                        if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null) {
                            if (match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                                edgeNode.setSourcePort(match.getTcpMatch().getSourcePortMatch().getPort());
                            } else if (match.getTcpMatch().getSourcePortMatch().getLowerPort() != 0
                                    && match.getTcpMatch().getSourcePortMatch().getUpperPort() != 0) {
                                edgeNode.setSourcePortStart(match.getTcpMatch().getSourcePortMatch().getLowerPort());
                                edgeNode.setSourcePortEnd(match.getTcpMatch().getSourcePortMatch().getUpperPort());
                            }
                        }
                        //udp
                        if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null) {
                            if (match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                                edgeNode.setDestPort(match.getUdpMatch().getDestinationPortMatch().getPort());
                            } else if (match.getUdpMatch().getDestinationPortMatch().getLowerPort() != 0
                                    && match.getUdpMatch().getDestinationPortMatch().getUpperPort() != 0) {
                                edgeNode.setDestPortStart(match.getUdpMatch().getDestinationPortMatch().getLowerPort());
                                edgeNode.setDestPortEnd(match.getUdpMatch().getDestinationPortMatch().getUpperPort());
                            }
                        }

                        if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null) {
                            if (match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                                edgeNode.setSourcePort(match.getUdpMatch().getSourcePortMatch().getPort());
                            } else if (match.getUdpMatch().getSourcePortMatch().getLowerPort() != 0
                                    && match.getUdpMatch().getSourcePortMatch().getUpperPort() != 0) {
                                edgeNode.setSourcePortStart(match.getUdpMatch().getSourcePortMatch().getLowerPort());
                                edgeNode.setSourcePortEnd(match.getUdpMatch().getSourcePortMatch().getUpperPort());
                            }
                        }

                        if ((match.getIpv4Match() != null && match.getIpv4Match().getSourceIp() != null)) {
                            endpoint = match.getIpv4Match().getSourceIp();
                        } else if (match.getIpv6Match() != null && match.getIpv6Match().getSourceIp() != null) {
                            endpoint = match.getIpv6Match().getSourceIp();
                        } else if (match.getIetfMudMatch().getController() != null &&
                                (match.getIetfMudMatch().getController().contains(MUD_URN))) {
                            endpoint = match.getIetfMudMatch().getController();
                        }

                        deviceNode.addNode(DeviceNode.Directions.FROM_LOCAL, endpoint.replace("/32",""), edgeNode);
                    } else {
                        // FROM INTERNET
                        EdgeNode edgeNode = new EdgeNode();
                        String endpoint = WILD_CARD;

                        String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
                                .getEtherType();
                        edgeNode.setEthType(Integer.parseInt(etherType.substring(2), 16));

                        if (match.getIpv4Match() != null &&
                                match.getIpv4Match().getProtocol() != 0) {
                            edgeNode.setEthType(Integer.parseInt(Constants.ETH_TYPE_IPV4.substring(2), 16));
                            edgeNode.setIpProtocol(match.getIpv4Match().getProtocol());
                        }

                        if (match.getIpv6Match() != null) {
                            edgeNode.setEthType(Integer.parseInt(Constants.ETH_TYPE_IPV6.substring(2), 16));
                            edgeNode.setIpProtocol(match.getIpv6Match().getProtocol());
                        }

                        //tcp
                        if (match.getTcpMatch() != null &&
                                match.getTcpMatch().getDestinationPortMatch() != null) {
                            if (match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                                edgeNode.setDestPort(match.getTcpMatch().getDestinationPortMatch().getPort());
                            } else if (match.getTcpMatch().getDestinationPortMatch().getLowerPort() != 0
                                    && match.getTcpMatch().getDestinationPortMatch().getUpperPort() != 0) {
                                edgeNode.setDestPortStart(match.getTcpMatch().getDestinationPortMatch().getLowerPort());
                                edgeNode.setDestPortEnd(match.getTcpMatch().getDestinationPortMatch().getUpperPort());
                            }
                        }

                        if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null) {
                            if (match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                                edgeNode.setSourcePort(match.getTcpMatch().getSourcePortMatch().getPort());
                            } else if (match.getTcpMatch().getSourcePortMatch().getLowerPort() != 0
                                    && match.getTcpMatch().getSourcePortMatch().getUpperPort() != 0) {
                                edgeNode.setSourcePortStart(match.getTcpMatch().getSourcePortMatch().getLowerPort());
                                edgeNode.setSourcePortEnd(match.getTcpMatch().getSourcePortMatch().getUpperPort());
                            }
                        }
                        //udp
                        if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null) {
                            if (match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                                edgeNode.setDestPort(match.getUdpMatch().getDestinationPortMatch().getPort());
                            } else if (match.getUdpMatch().getDestinationPortMatch().getLowerPort() != 0
                                    && match.getUdpMatch().getDestinationPortMatch().getUpperPort() != 0) {
                                edgeNode.setDestPortStart(match.getUdpMatch().getDestinationPortMatch().getLowerPort());
                                edgeNode.setDestPortEnd(match.getUdpMatch().getDestinationPortMatch().getUpperPort());
                            }
                        }

                        if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null) {
                            if (match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                                edgeNode.setSourcePort(match.getUdpMatch().getSourcePortMatch().getPort());
                            } else if (match.getUdpMatch().getSourcePortMatch().getLowerPort() != 0
                                    && match.getUdpMatch().getSourcePortMatch().getUpperPort() != 0) {
                                edgeNode.setSourcePortStart(match.getUdpMatch().getSourcePortMatch().getLowerPort());
                                edgeNode.setSourcePortEnd(match.getUdpMatch().getSourcePortMatch().getUpperPort());
                            }
                        }

                        if (match.getIpv4Match() != null && match.getIpv4Match().getSourceIp() != null) {
                            endpoint = match.getIpv4Match().getSourceIp();
                        } else if (match.getIpv4Match() != null && match.getIpv4Match().getSrcDnsName() != null) {
                            endpoint = match.getIpv4Match().getSrcDnsName();
                        } else if (match.getIpv6Match() != null && match.getIpv6Match().getSourceIp() != null) {
                            endpoint = match.getIpv6Match().getSourceIp();
                        } else if (match.getIpv6Match() != null && match.getIpv6Match().getSrcDnsName() != null) {
                            endpoint = match.getIpv6Match().getSrcDnsName();
                        }
                        deviceNode.addNode(DeviceNode.Directions.FROM_INTERNET, endpoint.replace("/32",""), edgeNode);
                    }
                }
            }
        }

        return deviceNode;

    }



    private void writeCountRaw(List<String> records, String fileName) throws IOException {
        File file = new File(fileName);
        FileWriter writer = new FileWriter(file, true);
        // System.out.println("Writing raw... ");
        write(records, writer);
    }


    private void writeDeviceVariationCountRaw(List<String> records) throws IOException {
        File file = new File(deviceVariationCounterfilename);
        FileWriter writer = new FileWriter(file, true);
        //System.out.println("Writing raw... ");
        write(records, writer);
    }

    private void writeCompareDeviceVariationCountRaw(String compareDeviceName, List<String> records) throws IOException {
        String fileName = currentPath + File.separator + "result" + File.separator + compareDeviceName + "_VariationCounter.csv";
        File file = new File(fileName);
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

    private static double round(double value) {

        long factor = (long) Math.pow(10, 1);
        value = value * factor;
        long tmp = Math.round(value);
        return (double) tmp / factor;
    }

    //TODO simple method to test this.
    private boolean isIp(String endpoint) {
        String ip = endpoint.replace(":", "").replace(".", "");
        try {
            long x = Long.parseLong(ip);
            return true;
        } catch (NumberFormatException e) {
            try {
                long x = Long.parseLong(ip, 16);
                return true;
            } catch (NumberFormatException ex) {
                return false;
            }

        }
    }

//    private DeviceNode removeRedundancies(DeviceNode deviceNode) {
//        deviceNode = deviceNode.getEndpointOptimizedNode();
//        DeviceNode optimalDeviceNode = new DeviceNode(deviceNode.value);
//        for (DeviceNode.Directions direction: DeviceNode.Directions.values()) {
//
//            //first optimize across edges
//            List<EndpointNode> endpointNodes = deviceNode.getEndpointNodes(direction);
//            EndpointNode wildcardedEndpoint = null;
//            for (EndpointNode endpointNode : endpointNodes) {
//                List<EdgeNode> optimalEdges = new ArrayList<>();
//                List<EdgeNode> tobeRemoved = new ArrayList<>();
//                for (EdgeNode edgeNode: endpointNode.getEdges()) {
//                    boolean ignore = false;
//                    for (EdgeNode optimalEdge: optimalEdges) {
//                        if (optimalEdge.isMatching(edgeNode)) {
//                            ignore = true;
//                        }
//
//                        if (!ignore && edgeNode.isMatching(optimalEdge)) {
//                            tobeRemoved.add(edgeNode);
//                        }
//                    }
//
//                    if (!ignore) {
//                        optimalEdges.add(edgeNode);
//                    }
//                }
//                while (tobeRemoved.size() > 0) {
//                    int index = -1;
//                    for (int i = 0; i < optimalEdges.size(); i++) {
//                        if (optimalEdges.get(i).isAbsoluteMatching(tobeRemoved.get(0))) {
//                            index = i;
//                            break;
//                        }
//                    }
//                    if (index > -1) {
//                        optimalEdges.remove(index);
//                        tobeRemoved.remove(0);
//                    }
//                }
//                endpointNode.setEdges(optimalEdges);
//                if (endpointNode.getValue().equals("*")) {
//                    wildcardedEndpoint = endpointNode;
//                }
//            }
//
//            //optimize over the wild carded endpoints
//
//            if (wildcardedEndpoint != null) {
//                for (EndpointNode endpointNode : endpointNodes) {
//                    if (!endpointNode.getValue().equals("*")) {
//                        List<EdgeNode> optimalEdges = new ArrayList<>();
//
//                        for (EdgeNode edgeNode : endpointNode.getEdges()) {
//                            boolean wildcardfound = false;
//                            for (EdgeNode wildcardEdge : wildcardedEndpoint.getEdges()) {
//                                if (wildcardEdge.isMatching(edgeNode)) {
//                                    wildcardfound = true;
//                                }
//                            }
//                            if (!wildcardfound) {
//                                optimalEdges.add(edgeNode);
//                            }
//                        }
//
//                        endpointNode.setEdges(optimalEdges);
//                    }
//                }
//            }
//
//            //recalculate the counts
//            for (EndpointNode endpointNode : endpointNodes) {
//                if (endpointNode.getEdges().size() > 0) {
//                    optimalDeviceNode.addNode(direction, endpointNode.getValue(), endpointNode.getEdges());
//                }
//
//            }
//        }
//        return optimalDeviceNode;
//    }
//
//    private DeviceNode findOptimalStructure(DeviceNode deviceNode, DeviceNode mud) {
//        DeviceNode structuredNode = new DeviceNode(deviceNode.value + "tmp");
//        mud = mud.getEndpointOptimizedNode();
//        deviceNode = deviceNode.getEndpointOptimizedNode();
//
//        for (DeviceNode.Directions direction : DeviceNode.Directions.values()) {
//
//            for (EndpointNode endpointNode: deviceNode.getEndpointNodes(direction)) {
//                for (EdgeNode edgeNode : endpointNode.getEdges()) {
//                    EndpointNode retrievedNode = mud.getMatchingEndpointNode(direction, endpointNode.getValue(), edgeNode);
//                    if (retrievedNode == null) {
//                        retrievedNode = mud.getMatchingEndpointNode(direction, "*", edgeNode);
//                    }
//                    if (retrievedNode != null) {
//                        for (EdgeNode node : retrievedNode.getEdges()) {
//                            if (structuredNode.getAbsoluteMatchingEndpointNode(direction, retrievedNode.getValue(), node)
//                                    == null) {
//                                structuredNode.addNode(direction, retrievedNode.getValue(), node);
//                            }
//                        }
//                    } else {
//                        retrievedNode = ssdpNode.getMatchingEndpointNode(direction, endpointNode.getValue(), edgeNode);
//                        if (retrievedNode == null) {
//                            structuredNode.addNode(direction, endpointNode.getValue(), edgeNode);
//                        }
//                    }
//
//                }
//            }
//        }
//        return structuredNode;
//    }
//
//
//
//    private DeviceNode difference(DeviceNode deviceNode, DeviceNode mud) {
//        DeviceNode structuredNode = new DeviceNode(deviceNode.value);
//        mud = mud.getEndpointOptimizedNode();
//        deviceNode = deviceNode.getEndpointOptimizedNode();
//        for (DeviceNode.Directions direction : DeviceNode.Directions.values()) {
//
//            for (EndpointNode endpointNode: deviceNode.getEndpointNodes(direction)) {
//                EndpointNode fetchedNode = mud.getEndpointNode(direction, endpointNode.getValue());
//                if (fetchedNode == null) {
//                    structuredNode.addNode(direction, endpointNode.getValue(), endpointNode.getEdges());
//                } else {
//                    for (EdgeNode edge : endpointNode.getEdges()) {
//                        boolean matchFound = false;
//                        for (EdgeNode mudEdge : fetchedNode.getEdges()) {
//                             if (mudEdge.isMatching(edge)) {
//                                 matchFound = true;
//                                 break;
//                             }
//                        }
//                        if (!matchFound) {
//                            EndpointNode retrievedNode = ssdpNode.getMatchingEndpointNode(direction,
//                                    endpointNode.getValue(), edge);
//                            if (retrievedNode == null) {
//                                structuredNode.addNode(direction, endpointNode.getValue(), edge);
//                            }
//
//                        }
//                    }
//                }
//            }
//        }
//        return  structuredNode;
//    }

    private DeviceNode removeRedundancies(DeviceNode deviceNode) {

        DeviceNode optimalDeviceNode = new DeviceNode(deviceNode.value);
        for (DeviceNode.Directions direction: DeviceNode.Directions.values()) {

            //first optimize across edges
            List<EndpointNode> endpointNodes = deviceNode.getEndpointNodes(direction);
            EndpointNode wildcardedEndpoint = null;
            for (EndpointNode endpointNode : endpointNodes) {
                List<EdgeNode> optimalEdges = new ArrayList<>();
                List<EdgeNode> tobeRemoved = new ArrayList<>();
                for (EdgeNode edgeNode: endpointNode.getEdges()) {
                    boolean ignore = false;
                    for (EdgeNode optimalEdge: optimalEdges) {
                        if (optimalEdge.isMatching(edgeNode)) {
                            ignore = true;
                        }

                        if (!ignore && edgeNode.isMatching(optimalEdge)) {
                            tobeRemoved.add(edgeNode);
                        }
                    }

                    if (!ignore) {
                        optimalEdges.add(edgeNode);
                    }
                }
                while (tobeRemoved.size() > 0) {
                    int index = -1;
                    for (int i = 0; i < optimalEdges.size(); i++) {
                        if (optimalEdges.get(i).isAbsoluteMatching(tobeRemoved.get(0))) {
                            index = i;
                            break;
                        }
                    }
                    if (index > -1) {
                        optimalEdges.remove(index);
                        tobeRemoved.remove(0);
                    }
                }
                endpointNode.setEdges(optimalEdges);
                if (endpointNode.getValue().equals("*")) {
                    wildcardedEndpoint = endpointNode;
                }
            }

            //optimize over the wild carded endpoints

            if (wildcardedEndpoint != null) {
                for (EndpointNode endpointNode : endpointNodes) {
                    if (!endpointNode.getValue().equals("*")) {
                        List<EdgeNode> optimalEdges = new ArrayList<>();

                        for (EdgeNode edgeNode : endpointNode.getEdges()) {
                            boolean wildcardfound = false;
                            for (EdgeNode wildcardEdge : wildcardedEndpoint.getEdges()) {
                                if (wildcardEdge.isMatching(edgeNode)) {
                                    wildcardfound = true;
                                }
                            }
                            if (!wildcardfound) {
                                optimalEdges.add(edgeNode);
                            }
                        }

                        endpointNode.setEdges(optimalEdges);
                    }
                }
            }

            //recalculate the counts
            for (EndpointNode endpointNode : endpointNodes) {
                if (endpointNode.getEdges().size() > 0) {
                    optimalDeviceNode.addNode(direction, endpointNode.getValue(), endpointNode.getEdges());
                }

            }
        }
        return optimalDeviceNode;
    }


    private DeviceNode findOptimalStructure(DeviceNode deviceNode, DeviceNode mud) {
        DeviceNode structuredNode = new DeviceNode(deviceNode.value + "tmp");

        for (DeviceNode.Directions direction : DeviceNode.Directions.values()) {

            for (EndpointNode endpointNode: deviceNode.getEndpointNodes(direction)) {
                for (EdgeNode edgeNode : endpointNode.getEdges()) {
                    EndpointNode retrievedNode = mud.getMatchingEndpointNode(direction, endpointNode.getValue(), edgeNode);
                    if (retrievedNode == null) {
                        retrievedNode = mud.getMatchingEndpointNode(direction, "*", edgeNode);
                    }
                    if (retrievedNode != null) {
                        for (EdgeNode node : retrievedNode.getEdges()) {
                            if (structuredNode.getAbsoluteMatchingEndpointNode(direction, retrievedNode.getValue(), node)
                                    == null) {
                                structuredNode.addNode(direction, retrievedNode.getValue(), node);
                            }
                        }
                    } else {
                        retrievedNode = ssdpNode.getMatchingEndpointNode(direction, endpointNode.getValue(), edgeNode);
                        if (retrievedNode == null) {
                            structuredNode.addNode(direction, endpointNode.getValue(), edgeNode);
                        }
                    }

                }
            }
        }
        return structuredNode;
    }



    private DeviceNode difference(DeviceNode deviceNode, DeviceNode mud) {
        DeviceNode structuredNode = new DeviceNode(deviceNode.value);

        for (DeviceNode.Directions direction : DeviceNode.Directions.values()) {

            for (EndpointNode endpointNode: deviceNode.getEndpointNodes(direction)) {
                EndpointNode fetchedNode = mud.getEndpointNode(direction, endpointNode.getValue());
                if (fetchedNode == null) {
                    structuredNode.addNode(direction, endpointNode.getValue(), endpointNode.getEdges());
                } else {
                    for (EdgeNode edge : endpointNode.getEdges()) {
                        boolean matchFound = false;
                        for (EdgeNode mudEdge : fetchedNode.getEdges()) {
                            if (mudEdge.isMatching(edge)) {
                                matchFound = true;
                                break;
                            }
                        }
                        if (!matchFound) {
                            EndpointNode retrievedNode = ssdpNode.getMatchingEndpointNode(direction,
                                    endpointNode.getValue(), edge);
                            if (retrievedNode == null) {
                                structuredNode.addNode(direction, endpointNode.getValue(), edge);
                            }

                        }
                    }
                }
            }
        }
        return  structuredNode;
    }

    private DeviceNode findOptimalStructureWithoutSSdp(DeviceNode deviceNode, DeviceNode mud) {
        DeviceNode structuredNode = new DeviceNode(deviceNode.value + "tmp");

        for (DeviceNode.Directions direction : DeviceNode.Directions.values()) {

            for (EndpointNode endpointNode: deviceNode.getEndpointNodes(direction)) {
                for (EdgeNode edgeNode : endpointNode.getEdges()) {
                    EndpointNode retrievedNode = mud.getMatchingEndpointNode(direction, endpointNode.getValue(), edgeNode);
                    if (retrievedNode == null) {
                        retrievedNode = mud.getMatchingEndpointNode(direction, "*", edgeNode);
                    }
                    if (retrievedNode != null) {
                        for (EdgeNode node : retrievedNode.getEdges()) {
                            if (structuredNode.getAbsoluteMatchingEndpointNode(direction, retrievedNode.getValue(), node)
                                    == null) {
                                structuredNode.addNode(direction, retrievedNode.getValue(), node);
                            }
                        }
                    } else {
                        structuredNode.addNode(direction, endpointNode.getValue(), edgeNode);
                    }

                }
            }
        }
        return structuredNode;
    }

    private DeviceNode differenceWithoutSSdp(DeviceNode deviceNode, DeviceNode mud) {
        DeviceNode structuredNode = new DeviceNode(deviceNode.value);

        for (DeviceNode.Directions direction : DeviceNode.Directions.values()) {

            for (EndpointNode endpointNode: deviceNode.getEndpointNodes(direction)) {
                EndpointNode fetchedNode = mud.getEndpointNode(direction, endpointNode.getValue());
                if (fetchedNode == null) {
                    structuredNode.addNode(direction, endpointNode.getValue(), endpointNode.getEdges());
                } else {
                    for (EdgeNode edge : endpointNode.getEdges()) {
                        boolean matchFound = false;
                        for (EdgeNode mudEdge : fetchedNode.getEdges()) {
                            if (mudEdge.isMatching(edge)) {
                                matchFound = true;
                                break;
                            }
                        }
                        if (!matchFound) {
                            structuredNode.addNode(direction, endpointNode.getValue(), edge);
                        }
                    }
                }
            }
        }
        return  structuredNode;
    }
}
