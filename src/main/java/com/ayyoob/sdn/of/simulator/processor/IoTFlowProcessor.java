package com.ayyoob.sdn.of.simulator.processor;

import com.ayyoob.sdn.of.simulator.Constants;
import com.ayyoob.sdn.of.simulator.OFFlow;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.*;

public class IoTFlowProcessor {
	//b4750eece5a9-dnsworkers.csv
	private static Set<OFFlow> ofFlowSet = new LinkedHashSet<>();
	private static String deviceMac = "e0:76:d0:3f:00:ae";
	private static String gateway = "14:cc:20:51:33:ea";
	public static void main(String[] args) {
		String currentPath = Paths.get(".").toAbsolutePath().normalize().toString();

		String workingDirectory = currentPath + File.separator + "result"
				+ File.separator + "augustdoorbellcam" + File.separator;
		ClassLoader classLoader = IoTFlowProcessor.class.getClassLoader();
		File file = new File( workingDirectory + deviceMac +"_ipflows.csv");
		File dnsFile = new File( workingDirectory + deviceMac.replace(":", "")+"-dnsworkers.csv");

		File dnsIpFile = new File( workingDirectory + deviceMac.replace(":", "")+"-dnsworker.csv");
		File icmpIpFile = new File( workingDirectory + deviceMac.replace(":", "")+"-icmpworker.csv");
		File ntpIpFile = new File( workingDirectory + deviceMac.replace(":", "")+"-ntpworker.csv");

		Map<String,String> ipDns = new HashMap<>();
		try (BufferedReader br = new BufferedReader(new FileReader(dnsFile))) {
			String line;
			while ((line = br.readLine()) != null) {
				// process the line.
				//"srcMac,dstMac,ethType,vlanId,srcIp,dstIp,ipProto,srcPort,dstPort,priority"
				if (!line.isEmpty()) {
					String vals[] = line.split(",");
					if (ipDns.get(vals[1]) == null ) {
						ipDns.put(vals[1], vals[0]);
					} else {
						ipDns.put(vals[1], ipDns.get(vals[1]) + "|" + vals[0]);
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		Set<String> dnsIps = new LinkedHashSet<>();
		try (BufferedReader br = new BufferedReader(new FileReader(dnsIpFile))) {
			String line;
			while ((line = br.readLine()) != null) {
				// process the line.
				//"srcMac,dstMac,ethType,vlanId,srcIp,dstIp,ipProto,srcPort,dstPort,priority"
				if (!line.isEmpty()) {
					String val = ipDns.get(line.split(",")[0]) == null?
							line.split(",")[0] :ipDns.get(line.split(",")[0]);
					dnsIps.add(val);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		Set<String> icmpIps = new LinkedHashSet<>();
		try (BufferedReader br = new BufferedReader(new FileReader(icmpIpFile))) {
			String line;
			while ((line = br.readLine()) != null) {
				// process the line.
				//"srcMac,dstMac,ethType,vlanId,srcIp,dstIp,ipProto,srcPort,dstPort,priority"
				if (!line.isEmpty()) {
					String val = ipDns.get(line.split(",")[0]) == null?
							line.split(",")[0] :ipDns.get(line.split(",")[0]);
					icmpIps.add(val);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		Set<String> ntpIps = new LinkedHashSet<>();
		try (BufferedReader br = new BufferedReader(new FileReader(ntpIpFile))) {
			String line;
			while ((line = br.readLine()) != null) {
				// process the line.
				//"srcMac,dstMac,ethType,vlanId,srcIp,dstIp,ipProto,srcPort,dstPort,priority"
				if (!line.isEmpty()) {
					String val = ipDns.get(line.split(",")[0]) == null?
							line.split(",")[0] :ipDns.get(line.split(",")[0]);
					ntpIps.add(val);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			String line;
			br.readLine();
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
					ofFlow.setIpProto(vals[6]);
					ofFlow.setSrcPort(vals[7]);
					ofFlow.setDstPort(vals[8]);
					ofFlow.setPriority(Integer.parseInt(vals[9]));
					ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);

					if(vals[6].equals(Constants.UDP_PROTO) && (vals[0].equals(gateway) || vals[1].equals(gateway))
							&& (vals[7].equals(Constants.DNS_PORT) || vals[8].equals(Constants.DNS_PORT ))) {
						if  (vals[0].equals(gateway)) {
							ofFlow.setSrcIp(getString(dnsIps));
						} else {
							ofFlow.setDstIp(getString(dnsIps));
						}
					} else if(vals[6].equals(Constants.UDP_PROTO) && (vals[0].equals(gateway) || vals[1].equals(gateway))
							&& (vals[7].equals(Constants.NTP_PORT) || vals[8].equals(Constants.NTP_PORT ))) {
						if  (vals[0].equals(gateway)) {
							ofFlow.setSrcIp(getString(ntpIps));
						} else {
							ofFlow.setDstIp(getString(ntpIps));
						}
					} else if(vals[6].equals(Constants.ICMP_PROTO) && (vals[0].equals(gateway) || vals[1].equals(gateway))) {
						if  (vals[0].equals(gateway)) {
							ofFlow.setSrcIp(getString(icmpIps));
						} else {
							ofFlow.setDstIp(getString(icmpIps));
						}
					} else {
						ofFlow.setSrcIp(ipDns.get(vals[4]) != null ?ipDns.get(vals[4]):vals[4]);
						ofFlow.setDstIp(ipDns.get(vals[5]) != null ?ipDns.get(vals[5]):vals[5]);
					}

					ofFlowSet.add(ofFlow);
					//OFController.getInstance().addFlow(dpId, ofFlow);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		for (OFFlow ofFlow : ofFlowSet) {
			ofFlow.setVlanId("NIL");
			String flowString = ofFlow.getFlowStringWithoutFlowStat();
			flowString= flowString.replace(deviceMac, "<deviceMac>");
			flowString= flowString.replace(gateway, "<gatewayMac>");
			flowString= flowString.replace(",NIL,", ",");
			System.out.println("," + flowString + ",");
		}
	}

	private static String getString(Set<String> vals) {
		return "[" + String.join("|", vals) + "]";

	}
}
