package com.ayyoob.sdn.of.simulator;

import com.ayyoob.sdn.of.simulator.apps.ControllerApp;
import org.json.simple.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.*;

public class OFController {

    private static final  OFController ofController = new OFController();
    private static Map<String, OFSwitch> ofSwitchMap = new HashMap<String, OFSwitch>();
    private static Map<String, Integer> packetTransmittionMap = new HashMap<String, Integer>();
    private static List<ControllerApp> registeredApps = new ArrayList<ControllerApp>();
    private boolean packetLoggerEnabled = true;
    public static OFController getInstance() {
        return ofController;
    }

    private OFController() {

    }

    public Set<String> getSwitchIds() {
        return ofSwitchMap.keySet();
    }

    public void addSwitch(OFSwitch ofSwitch) {
        ofSwitchMap.put(ofSwitch.getDpid(), ofSwitch);
        packetTransmittionMap.put(ofSwitch.getDpid(), 0);
    }

    public OFSwitch getSwitch(String dpId) {
        return ofSwitchMap.get(dpId);
    }

    public void registerApps(ControllerApp controllerApp, JSONObject argument) {
        registeredApps.add(controllerApp);
        controllerApp.init(argument);
    }

    public List<OFFlow> getAllFlows(String dpId) {
        return ofSwitchMap.get(dpId).getAllFlows();
    }

    public void addFlow(String dpId, OFFlow ofFlow){
        ofSwitchMap.get(dpId).addFlow(ofFlow);
    }

    public void removeFlow(String dpId, OFFlow ofFlow) {
        ofSwitchMap.get(dpId).removeFlow(ofFlow);
    }

    public void clearAllFlows(String dpId) {
        ofSwitchMap.get(dpId).clearAllFlows();
    }

    public int  getNumperOfPackets(String dpId) {
        return packetTransmittionMap.get(dpId);
    }

    public void receive(String dpId, SimPacket packet) {
        int noOFpackets = packetTransmittionMap.get(dpId) +  1;
        packetTransmittionMap.put(dpId, noOFpackets);
        logPacket(packet);
        for (ControllerApp controllerApp : registeredApps) {
            controllerApp.process(dpId, packet);
        }

    }

    public void printStats() {
        String stats = "";
        for (String dpId : packetTransmittionMap.keySet()) {
            stats = "MacAddress:" + ofSwitchMap.get(dpId).getMacAddress()
                    + ", TransmittedPacketCountThroughController:" + getNumperOfPackets(dpId);
        }
        System.out.println(stats);
    }

    public void complete() {
        for (ControllerApp controllerApp: registeredApps) {
            controllerApp.complete();
        }
    }

    private void logPacket(SimPacket packet) {
        if (!packetLoggerEnabled) {
            return;
        }
        String currentPath = Paths.get(".").toAbsolutePath().normalize().toString();

        File workingDirectory = new File(currentPath + File.separator + "result");
        if (!workingDirectory.exists()) {
            workingDirectory.mkdir();
        }
        String filename = currentPath + File.separator + "result" + File.separator + "packetlog.txt";
        File file = new File(filename);
        FileWriter writer = null;
        try {
            writer = new FileWriter(file, true);
            writer.write(packet.getPacketInfo() + "\n");
            writer.flush();
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
