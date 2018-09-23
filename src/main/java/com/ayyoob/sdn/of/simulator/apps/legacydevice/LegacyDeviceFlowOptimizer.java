package com.ayyoob.sdn.of.simulator.apps.legacydevice;

import com.ayyoob.sdn.of.simulator.Constants;
import com.ayyoob.sdn.of.simulator.OFController;
import com.ayyoob.sdn.of.simulator.OFFlow;
import com.ayyoob.sdn.of.simulator.SimPacket;
import com.ayyoob.sdn.of.simulator.apps.StatListener;
import com.ayyoob.sdn.of.simulator.processor.mud.*;
import com.fasterxml.jackson.databind.ObjectMapper;
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
    private List<DeviceNode> identifiedDevices = new ArrayList<>();
    private String similarityCounterfilename;
    private String variationCounterfilename;
    private List<String> similarityCounterData = new ArrayList<>();
    private List<String> variationCounterData = new ArrayList<>();
    private String deviceVariationCounterfilename;
    private List<String> deviceVariationCounterData = new ArrayList<>();
    private List<String> alldeviceVariationCounterData = new ArrayList<>();
    private String deviceName ;
    private Map<String, List<String>> compareDevices = new HashMap<>();
    private String currentPath;


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
            for (String profileName : files) {
                String filePath = file.getAbsolutePath() + File.separator + profileName;
                byte[] encoded = new byte[0];
                try {
                    encoded = Files.readAllBytes(Paths.get(filePath));
                    String mudPayload = new String(encoded, Charset.defaultCharset());
                    DeviceNode deviceNode = processMUD(profileName.replace(".json", ""), mudPayload);
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
        deviceVariationCounterfilename = currentPath + File.separator + "result" + File.separator + deviceMac.replace(":", "") + "_DirectionVariationCounter.csv";
        String header = "time,TISimilarity,TIVariation,TIEndpointSimilarity,TIEndpointVariation" +
                ",FISimilarity,FIVariation,FIEndpointSimilarity,FIEndpointVariation" +
                ",TLSimilarity,TLVariation,TLEndpointSimilarity,TLEndpointVariation" +
                ",FLSimilarity,FLVariation,FLEndpointSimilarity,FLEndpointVariation" +
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
            optimizeDevice();
            String[] similarityInfo = calculateVariations();
            String perDevice = calculateVariations(deviceName);
            similarityCounterData.add(currentTime + similarityInfo[0]);
            variationCounterData.add(currentTime + similarityInfo[1]);
            deviceVariationCounterData.add(currentTime + perDevice);

            for (String key : compareDevices.keySet()) {
                String perCompareDevice = calculateVariations(key);
                compareDevices.get(key).add(currentTime + perCompareDevice);
            }
        }

        if (similarityCounterData.size() > 1000) {
            try {
                writeSimilarityCountRaw(similarityCounterData);
                writeVariationCountRaw(variationCounterData);
                writeDeviceVariationCountRaw(deviceVariationCounterData);
                for (String key : compareDevices.keySet()) {
                    writeCompareDeviceVariationCountRaw(key, compareDevices.get(key));
                    compareDevices.get(key).clear();
                }
                similarityCounterData.clear();
                variationCounterData.clear();
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
            for (EndpointNode endpointNode: endpointNodes) {
                if (endpointNode.getEdges().size() > endpointNode.getPreviousChecked()) {
                    List<EdgeNode> mudEdges = allMUDNode.getEdgeNodes(direction, endpointNode.getValue());
                    String newEndpoint = endpointNode.getValue();
                    if (mudEdges == null) {
                        mudEdges = allMUDNode.getEdgeNodes(direction, endpointNode.getValue() + "/32");
                    } if (mudEdges == null) {
                        mudEdges = allMUDNode.getEdgeNodes(direction, "*");
                        endpointsTobeOptimized.add(endpointNode);
                    }

                    if (mudEdges == null) {
                        // processs variation here TODO

                    } else {
                        List<EdgeNode> deviceEdges =  endpointNode.getEdges();
                        List<EdgeNode> matchingEdge = new ArrayList<>();
                        List<EdgeNode> notMatchingEdge = new ArrayList<>();
                        for (EdgeNode devEdge : deviceEdges) {
                            boolean exisitingNode = false;
                            for (EdgeNode existingMatchEdge : matchingEdge) {
                                if (existingMatchEdge.isMatching(devEdge)) {
                                    exisitingNode = true;
                                }
                            }
                            if (exisitingNode) {
                                continue;
                            }
                            boolean matchingFound = false;
                            Set<EdgeNode> multipleEdge = new HashSet<>();
                            for (EdgeNode mudEdge : mudEdges) {
                                if (mudEdge.isMatching(devEdge)) {
                                    multipleEdge.add(mudEdge);
                                    matchingFound = true;
                                }
                            }

                            if (!matchingFound) {
                                notMatchingEdge.add(devEdge);
                            } else if (multipleEdge.size() > 1) {

                                //find optimal edge
                                int sourcePort = -1;
                                int destPort = -1;
                                int protocol = -1;
                                for (EdgeNode edgeNode : multipleEdge) {
                                    if (edgeNode.getIpProtocol() > protocol) {
                                        protocol = edgeNode.getIpProtocol();
                                    }
                                    if (edgeNode.getSourcePort() > sourcePort) {
                                        sourcePort = edgeNode.getSourcePort();
                                    }
                                    if (edgeNode.getDestPort() > destPort) {
                                        destPort = edgeNode.getDestPort();
                                    }
                                }
                                devEdge.setSourcePort(sourcePort);
                                devEdge.setDestPort(destPort);
                                matchingEdge.add(devEdge);
                            } else {
                                matchingEdge.add((EdgeNode) multipleEdge.toArray()[0]);
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
                                if (nonMatchEdge.getSourcePort() != -1 && nonMatchEdge.getDestPort() != -1) {
                                    EdgeNode copyEdge = nonMatchEdge.clone();
                                    copyEdge.setSourcePort(-1);
                                    nonMatchEdge.setDestPort(-1);
                                    optimizeEdgeNode.add(copyEdge);
                                    optimizeEdgeNode.add(nonMatchEdge);
                                } else {
                                    optimizeEdgeNode.add(nonMatchEdge);
                                }
                            }
                        }

                        matchingEdge.addAll(optimizeEdgeNode);
                        deviceNode.numberOFEdgeNode = deviceNode.numberOFEdgeNode - endpointNode.getEdges().size()
                                + matchingEdge.size();
                        endpointNode.setEdges(matchingEdge);
                    }
                    endpointNode.setPreviousChecked(endpointNode.getEdges().size());
                }
            }

            // optimize endpoints
            if (endpointsTobeOptimized.size() > 0) {
                List<EdgeNode> edges = new ArrayList<>();
                for (EndpointNode endpointNode : endpointsTobeOptimized) {
                    edges.addAll(endpointNode.getEdges());
                    deviceNode.removeNode(direction, endpointNode.getValue());
                }
                EndpointNode endpointNode = deviceNode.getEndpointNode(direction, "*");
                deviceNode.addNode(direction, "*", edges);
            }

        }
    }

    private String[] calculateVariations() {
        DeviceNode deviceNode = LegacyDeviceIdentifier.deviceNode;
        String[] values = new String[2];
        values[0] = "";
        values[1] = "";
        for (DeviceNode existingDevice : identifiedDevices) {
            // A - device to be discovered.
            //B - identified device.
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
            values[0] = values[0]+ "," + round(similarity) ;
            values[1] = values[1] +  ","+ round(variation) ;
        }
        return values;
    }


    private String calculateVariations(String deviceName) {
        String variations = "";
        DeviceNode deviceNode = LegacyDeviceIdentifier.deviceNode;
        DeviceNode referedDevice = null;

        for (DeviceNode existingDevice : identifiedDevices) {
            if (existingDevice.getValue().equals(deviceName)) {
                referedDevice = existingDevice;

                break;
            }
        }
        if (referedDevice != null) {
            int numberOfARules = deviceNode.numberOFEdgeNode;
            int numberOfBRules = referedDevice.numberOFEdgeNode;
            int numberOfAIntersectionBRules = 0;

            int numberOFAEndpoints = 0;
            int numberOFBEndpoints = 0;
            int numberOfAIntersectionBEndpoints = 0;

            for (DeviceNode.Directions direction : DeviceNode.Directions.values()) {
                int numberOfARulesDirection = 0;
                int numberOfBRulesDirection = referedDevice.getDirectionEdgeCount(direction);
                int numberOfAIntersectionBRulesDirection = 0;

                List<EndpointNode> discoveredEndpoints = deviceNode.getEndpointNodes(direction);

                int numberOfAEndpointDirection = discoveredEndpoints.size();
                int numberOfBEndpointDirection = referedDevice.getEndpointNodes(direction).size();
                ;
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

            }
            double similarity = (numberOfAIntersectionBRules * 100.0) / numberOfBRules;
            double variation = ((numberOfARules - numberOfAIntersectionBRules) * 100.0) / numberOfARules;

            double similarityEndpoint = (numberOfAIntersectionBEndpoints * 100.0) / numberOFBEndpoints;
            double variationEndpoint = ((numberOFAEndpoints - numberOfAIntersectionBEndpoints) * 100.0) / numberOFAEndpoints;

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
        optimizeDevice();
        String[] similarityInfo = calculateVariations();
        String perDevice = calculateVariations(deviceName);
        similarityCounterData.add(currentTime + similarityInfo[0]);
        variationCounterData.add(currentTime + similarityInfo[1]);
        deviceVariationCounterData.add(currentTime + perDevice);

        for (String key : compareDevices.keySet()) {
            String perCompareDevice = calculateVariations(key);
            compareDevices.get(key).add(currentTime + perCompareDevice);
        }

        try {
            writeVariationCountRaw(variationCounterData);
            writeSimilarityCountRaw(similarityCounterData);
            writeDeviceVariationCountRaw(deviceVariationCounterData);
            for (String key : compareDevices.keySet()) {
                writeCompareDeviceVariationCountRaw(key, compareDevices.get(key));
            }
        } catch (IOException e) {
            e.printStackTrace();
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
                                match.getTcpMatch().getDestinationPortMatch() != null
                                && match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                            edgeNode.setDestPort(match.getTcpMatch().getDestinationPortMatch().getPort());
                        }

                        if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null
                                && match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                            edgeNode.setSourcePort(match.getTcpMatch().getSourcePortMatch().getPort());
                        }
                        //udp
                        if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null
                                && match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                            edgeNode.setDestPort(match.getUdpMatch().getDestinationPortMatch().getPort());
                        }

                        if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null
                                && match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                            edgeNode.setSourcePort(match.getUdpMatch().getSourcePortMatch().getPort());
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
                                match.getTcpMatch().getDestinationPortMatch() != null
                                && match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                            edgeNode.setDestPort(match.getTcpMatch().getDestinationPortMatch().getPort());
                        }

                        if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null
                                && match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                            edgeNode.setSourcePort(match.getTcpMatch().getSourcePortMatch().getPort());
                        }
                        //udp
                        if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null
                                && match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                            edgeNode.setDestPort(match.getUdpMatch().getDestinationPortMatch().getPort());
                        }

                        if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null
                                && match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                            edgeNode.setSourcePort(match.getUdpMatch().getSourcePortMatch().getPort());
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
                                match.getTcpMatch().getDestinationPortMatch() != null
                                && match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                            edgeNode.setDestPort(match.getTcpMatch().getDestinationPortMatch().getPort());
                        }

                        if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null
                                && match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                            edgeNode.setSourcePort(match.getTcpMatch().getSourcePortMatch().getPort());
                        }
                        //udp
                        if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null
                                && match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                            edgeNode.setDestPort(match.getUdpMatch().getDestinationPortMatch().getPort());
                        }

                        if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null
                                && match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                            edgeNode.setSourcePort(match.getUdpMatch().getSourcePortMatch().getPort());
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
                                match.getTcpMatch().getDestinationPortMatch() != null
                                && match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
                            edgeNode.setDestPort(match.getTcpMatch().getDestinationPortMatch().getPort());
                        }

                        if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null
                                && match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
                            edgeNode.setSourcePort(match.getTcpMatch().getSourcePortMatch().getPort());
                        }
                        //udp
                        if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null
                                && match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
                            edgeNode.setDestPort(match.getUdpMatch().getDestinationPortMatch().getPort());
                        }

                        if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null
                                && match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
                            edgeNode.setSourcePort(match.getUdpMatch().getSourcePortMatch().getPort());
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

    private void writeSimilarityCountRaw(List<String> records) throws IOException {
        File file = new File(similarityCounterfilename);
        FileWriter writer = new FileWriter(file, true);
        // System.out.println("Writing raw... ");
        write(records, writer);
    }

    private void writeVariationCountRaw(List<String> records) throws IOException {
        File file = new File(variationCounterfilename);
        FileWriter writer = new FileWriter(file, true);
        //System.out.println("Writing raw... ");
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



}
