package com.ayyoob.sdn.of.simulator.apps;

import com.ayyoob.sdn.of.simulator.Constants;
import com.ayyoob.sdn.of.simulator.OFController;
import com.ayyoob.sdn.of.simulator.OFFlow;
import com.ayyoob.sdn.of.simulator.SimPacket;
import com.ayyoob.sdn.of.simulator.apps.mudflowdto.DeviceMUDFlowMap;
import com.ayyoob.sdn.of.simulator.processor.mud.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.simple.JSONObject;
import org.pcap4j.packet.namednumber.EtherType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class MudieFlowDeployer implements ControllerApp {

	private static final int FIXED_LOCAL_COMMUNICATION = 5;
	private static final int DEFAULT_LOCAL_COMMUNICATION = 4;
	private static final int FIXED_INTERNET_COMMUNICATION = 10;
	private static final int FIXED_LOCAL_CONTROLLER_COMMUNICATION = 11;
	private static final int DEFAULT_INTERNET_COMMUNICATION = 9;
	private static final int DYNAMIC_INTERNET_COMMUNICATION = 15000;
	private static final String MUD_URN = "urn:ietf:params:mud";
	private static long idleTimeout = 120000;
	private static boolean enabled = true;
	private static String deviceMac;
	private static String gatewayIp;
	private static String dpId;
	private Map<String, DeviceMUDFlowMap> deviceFlowMapHolder = new HashMap<>();

	@Override
	public void init(JSONObject jsonObject) {
		enabled = (Boolean) jsonObject.get("enable");
		idleTimeout = ((Long) jsonObject.get("idleTimeoutInSeconds")) * 1000L;
		if (!enabled) {
			return;
		}
		deviceMac = (String) jsonObject.get("deviceMac");
		gatewayIp = (String) jsonObject.get("gatewayIp");
		dpId = (String) jsonObject.get("dpId");

		String devices[] = ((String) jsonObject.get("devices")).split("\\|");
		String mudPath = (String) jsonObject.get("mudPath");
		ObjectMapper mapper = new ObjectMapper();
		for (String device : devices) {
			String dmac = device.split(",")[0];
			String path = mudPath + device.split(",")[1];
			try {
				byte[] encoded = Files.readAllBytes(Paths.get(path));
				String mudPayload = new String(encoded, Charset.defaultCharset());

				addMudConfigs(mudPayload, dmac, dpId, dpId);

				DeviceMUDFlowMap deviceMUDFlowMap = deviceFlowMapHolder.get(dmac);
				List<String> ars = new ArrayList<>();
				ars.add("174.129.217.97");
				deviceMUDFlowMap.addDnsIps("tunnel.xbcs.net", ars);

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public void process(String dpId, SimPacket packet) {
		if (!enabled) {
			return;
		}
		String srcMac = packet.getSrcMac();
		String destMac = packet.getDstMac();

		if (deviceFlowMapHolder.keySet().contains(srcMac) || deviceFlowMapHolder.keySet().contains(destMac)) {
			if (Constants.UDP_PROTO.equals(packet.getIpProto())
					&& packet.getSrcPort().equals(Constants.DNS_PORT)) {
				if (packet.getdnsQname() != null && packet.getDnsAnswers()!= null && packet.getDnsAnswers().size() > 0) {
					deviceFlowMapHolder.get(packet.getDstMac()).addDnsIps(packet.getdnsQname(), packet.getDnsAnswers());
				}

			} else if (packet.getEthType().equals(EtherType.IPV4.valueAsString())
					|| packet.getEthType().equals(EtherType.IPV6.valueAsString())) {
				if (srcMac.equals(dpId)) {
					//G2D
					String deviceMac = packet.getDstMac();
					DeviceMUDFlowMap deviceFlowMap = deviceFlowMapHolder.get(deviceMac);
					String dns = deviceFlowMap.getDns(packet.getSrcIp());
					String srcIp = packet.getSrcIp();
					if (dns != null) {
						packet.setSrcIp(dns);
					}
					List<OFFlow> ofFlows = deviceFlowMap.getFromInternetDynamicFlows();
					OFFlow ofFlow = getMatchingFlow(packet, ofFlows);
					if (ofFlow != null) {
						ofFlow = ofFlow.copy();
						ofFlow.setIdleTimeOut(idleTimeout);
						if (ofFlow.getSrcIp().equals(dns)) {
							ofFlow.setSrcIp(srcIp);
						}
						OFController.getInstance().addFlow(dpId, ofFlow);
//						System.out.println(OFController.getInstance().getSwitch(dpId).getCurrentTime() + "," +  ofFlow.getFlowString());
					} else {
						//logAnomalyPacket(seerPacket);
					}
				} else if (destMac.equals(dpId)) {
					//D2G
					String deviceMac = packet.getSrcMac();
					DeviceMUDFlowMap deviceMUDFlowMap = deviceFlowMapHolder.get(deviceMac);
					String dns = deviceMUDFlowMap.getDns(packet.getDstIp());
					String dstIp = packet.getDstIp();
					if (dns != null) {
						packet.setDstIp(dns);
					}
					List<OFFlow> ofFlows = deviceMUDFlowMap.getToInternetDynamicFlows();
					OFFlow ofFlow = getMatchingFlow(packet, ofFlows);
					if (ofFlow != null) {
						ofFlow = ofFlow.copy();
						ofFlow.setIdleTimeOut(idleTimeout);
						if (ofFlow.getDstIp().equals(dns)) {
							ofFlow.setDstIp(dstIp);
						}
						OFController.getInstance().addFlow(dpId, ofFlow);
//						System.out.println(OFController.getInstance().getSwitch(dpId).getCurrentTime() + "," +  ofFlow.getFlowString());
					} else {
						//logAnomalyPacket(seerPacket);
					}
				} else {
					//logAnomalyPacket(seerPacket);
				}
			}
		}
	}

	@Override
	public void complete() {

	}

	private void addMudConfigs(String mudPayload, String deviceMac, String switchMac, String dpId) throws IOException {
		DeviceMUDFlowMap deviceMUDFlowMap = processMUD(deviceMac, switchMac, mudPayload);
		List<OFFlow> ofFlows = new ArrayList<>();
		if (deviceMUDFlowMap != null) {
			ofFlows.addAll(deviceMUDFlowMap.getFromInternetStaticFlows());
			ofFlows.addAll(deviceMUDFlowMap.getToInternetStaticFlows());
			ofFlows.addAll(deviceMUDFlowMap.getFromLocalStaticFlows());
			ofFlows.addAll(deviceMUDFlowMap.getToLocalStaticFlows());
			ofFlows = sortFlowsWithPriority(ofFlows);
			for (OFFlow ofFlow: ofFlows) {
				OFController.getInstance().addFlow(dpId, ofFlow);
			}
			deviceFlowMapHolder.put(deviceMac, deviceMUDFlowMap);
		}
	}

	private DeviceMUDFlowMap processMUD(String deviceMac, String switchMac, String mudPayload) throws IOException {
		ObjectMapper mapper = new ObjectMapper();
		MudSpec mudSpec = mapper.readValue(mudPayload, MudSpec.class);
		DeviceMUDFlowMap deviceMUDFlowMap = loadMudSpec(deviceMac, switchMac, mudSpec);
		installInternetNetworkRules(deviceMac, switchMac, deviceMUDFlowMap);
		installLocalNetworkRules(deviceMac, switchMac, deviceMUDFlowMap);
		return deviceMUDFlowMap;
	}

	private DeviceMUDFlowMap loadMudSpec(String deviceMac, String switchMac, MudSpec mudSpec) {
		List<String> fromDevicePolicyNames = new ArrayList<>();
		List<String> toDevicePolicyNames = new ArrayList<>();
		for (AccessDTO accessDTO : mudSpec.getIetfMud().getFromDevicePolicy().getAccessList().getAccessDTOList()) {
			fromDevicePolicyNames.add(accessDTO.getName());
		}

		for (AccessDTO accessDTO : mudSpec.getIetfMud().getToDevicePolicy().getAccessList().getAccessDTOList()) {
			toDevicePolicyNames.add(accessDTO.getName());
		}

		List<OFFlow> fromInternetDynamicFlows = new ArrayList<>();
		List<OFFlow> toInternetDynamicFlows = new ArrayList<>();
		List<OFFlow> fromInternetStaticFlows = new ArrayList<>();
		List<OFFlow> toInternetStaticFlows = new ArrayList<>();
		List<OFFlow> fromLocalStaticFlows = new ArrayList<>();
		List<OFFlow> toLocalStaticFlows = new ArrayList<>();

		for (AccessControlListHolder accessControlListHolder : mudSpec.getAccessControlList().getAccessControlListHolder()) {
			if (fromDevicePolicyNames.contains(accessControlListHolder.getName())) {
				for (Ace ace : accessControlListHolder.getAces().getAceList()) {
					Match match = ace.getMatches();

					//filter local
					if (match.getIetfMudMatch() != null && (match.getIetfMudMatch().getController() != null
							|| match.getIetfMudMatch().getLocalNetworks() != null)) {

						//install local network related rules here
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
								.getEtherType();
						ofFlow.setEthType(etherType);
						ofFlow.setPriority(FIXED_LOCAL_COMMUNICATION);
						if (match.getIpv4Match() != null &&
								match.getIpv4Match().getProtocol() != 0) {

							ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
							ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
						}

						if (match.getIpv6Match() != null) {
							ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
							ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
						}

						if (match.getEthMatch() != null) {
							if (match.getEthMatch().getEtherType() != null) {
								ofFlow.setEthType(match.getEthMatch().getEtherType());
							}
							if (match.getEthMatch().getSrcMacAddress() != null) {
								ofFlow.setSrcMac(match.getEthMatch().getSrcMacAddress());
							}
							if (match.getEthMatch().getDstMacAddress() != null) {
								ofFlow.setDstMac(match.getEthMatch().getDstMacAddress());
							}

						}
						//tcp
						if (match.getTcpMatch() != null &&
								match.getTcpMatch().getDestinationPortMatch() != null
								&& match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
						}

						if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null
								&& match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
						}
						//udp
						if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null
								&& match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
						}

						if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null
								&& match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
						}

						if ((match.getIpv4Match() != null && match.getIpv4Match().getDestinationIp() != null)) {
							ofFlow.setDstIp(match.getIpv4Match().getDestinationIp());
						} else if (match.getIpv6Match() != null && match.getIpv6Match().getDestinationIp() != null) {
							ofFlow.setDstIp(match.getIpv6Match().getDestinationIp());
						} else if (match.getIetfMudMatch().getController() != null &&
								(match.getIetfMudMatch().getController().contains(MUD_URN))) {
							ofFlow.setDstIp(gatewayIp);
							ofFlow.setPriority(FIXED_LOCAL_CONTROLLER_COMMUNICATION);
						}

						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						toLocalStaticFlows.add(ofFlow);

					} else {
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						ofFlow.setDstMac(switchMac);

						String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
								.getEtherType();
						ofFlow.setEthType(etherType);
						if (match.getIpv4Match() != null &&
								match.getIpv4Match().getProtocol() != 0) {
							ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
							ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
						}

						if (match.getIpv6Match() != null) {
							ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
							ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
						}

						//tcp
						if (match.getTcpMatch() != null && match.getTcpMatch().getDestinationPortMatch() != null
								&& match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
						}

						if (match.getTcpMatch() != null && match.getTcpMatch().getSourcePortMatch() != null
								&& match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
						}
						//udp
						if (match.getUdpMatch() != null && match.getUdpMatch().getDestinationPortMatch() != null
								&& match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());

						}

						if (match.getUdpMatch() != null && match.getUdpMatch().getSourcePortMatch() != null
								&& match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
						}

						if (match.getIpv4Match() != null && match.getIpv4Match().getDestinationIp() != null) {
							ofFlow.setDstIp(match.getIpv4Match().getDestinationIp());
							ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
						} else if (match.getIpv4Match() != null && match.getIpv4Match().getDstDnsName() != null) {
							ofFlow.setDstIp(match.getIpv4Match().getDstDnsName());
							ofFlow.setPriority(DYNAMIC_INTERNET_COMMUNICATION);
						} else if (match.getIpv6Match() != null &&
								match.getIpv6Match().getDestinationIp() != null) {
							ofFlow.setDstIp(match.getIpv6Match().getDestinationIp());
							ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
						} else if (match.getIpv6Match() != null &&
								match.getIpv6Match().getDstDnsName() != null) {
							ofFlow.setDstIp(match.getIpv6Match().getDstDnsName());
							ofFlow.setPriority(DYNAMIC_INTERNET_COMMUNICATION);
						} else {
							ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
						}
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						if (FIXED_INTERNET_COMMUNICATION == ofFlow.getPriority()) {
							toInternetStaticFlows.add(ofFlow);
						} else {
							toInternetDynamicFlows.add(ofFlow);
						}

					}
				}
			} else if (toDevicePolicyNames.contains(accessControlListHolder.getName())) {

				for (Ace ace : accessControlListHolder.getAces().getAceList()) {
					Match match = ace.getMatches();

					//filter local
					if (match.getIetfMudMatch() != null && (match.getIetfMudMatch().getController() != null
							|| match.getIetfMudMatch().getLocalNetworks() != null)) {
						//install local network related rules here
						OFFlow ofFlow = new OFFlow();
						ofFlow.setDstMac(deviceMac);
						ofFlow.setPriority(FIXED_LOCAL_COMMUNICATION);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);

						if (match.getIpv4Match() != null &&
								match.getIpv4Match().getProtocol() != 0) {
							ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
							ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
						}

						if (match.getIpv6Match() != null) {
							ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
							ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
						}

						//tcp
						if (match.getTcpMatch() != null &&
								match.getTcpMatch().getDestinationPortMatch() != null
								&& match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
						}

						if (match.getTcpMatch() != null &&
								match.getTcpMatch().getSourcePortMatch() != null
								&& match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
						}
						//udp
						if (match.getUdpMatch() != null &&
								match.getUdpMatch().getDestinationPortMatch() != null
								&& match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
						}

						if (match.getUdpMatch() != null &&
								match.getUdpMatch().getSourcePortMatch() != null
								&& match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
							if (ofFlow.getSrcPort().equals(Constants.DNS_PORT)) {
								ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
							}
						}


						if ((match.getIpv4Match() != null && match.getIpv4Match().getSourceIp() != null)) {
							ofFlow.setSrcIp(match.getIpv4Match().getSourceIp());
						} else if (match.getIpv6Match() != null && match.getIpv6Match().getSourceIp() != null) {
							ofFlow.setSrcIp(match.getIpv6Match().getSourceIp());
						} else if (match.getIetfMudMatch().getController() != null &&
								(match.getIetfMudMatch().getController().contains(MUD_URN))) {
							ofFlow.setSrcIp(gatewayIp);
							ofFlow.setPriority(FIXED_LOCAL_CONTROLLER_COMMUNICATION);
						}
						fromLocalStaticFlows.add(ofFlow);
					} else {
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(switchMac);
						ofFlow.setDstMac(deviceMac);
						String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
								.getEtherType();
						ofFlow.setEthType(etherType);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						if (match.getIpv4Match() != null &&
								match.getIpv4Match().getProtocol() != 0) {

							ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
							ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
						}

						if (match.getIpv6Match() != null) {
							ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
							ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
						}

						//tcp
						if (match.getTcpMatch() != null &&
								match.getTcpMatch().getDestinationPortMatch() != null
								&& match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
						}

						if (match.getTcpMatch() != null &&
								match.getTcpMatch().getSourcePortMatch() != null
								&& match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
						}
						//udp
						if (match.getUdpMatch() != null &&
								match.getUdpMatch().getDestinationPortMatch() != null
								&& match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
						}

						if (match.getUdpMatch() != null &&
								match.getUdpMatch().getSourcePortMatch() != null
								&& match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
							if (ofFlow.getSrcPort().equals(Constants.DNS_PORT)) {
								ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
							}
						}

						if (match.getIpv4Match() != null && match.getIpv4Match().getSourceIp() != null) {
							ofFlow.setSrcIp(match.getIpv4Match().getSourceIp());
							ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
						} else if (match.getIpv4Match() != null && match.getIpv4Match().getSrcDnsName() != null) {
							ofFlow.setSrcIp(match.getIpv4Match().getSrcDnsName());
							ofFlow.setPriority(DYNAMIC_INTERNET_COMMUNICATION);
						} else if (match.getIpv6Match() != null && match.getIpv6Match().getSourceIp() != null) {
							ofFlow.setSrcIp(match.getIpv6Match().getSourceIp());
							ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
						} else if (match.getIpv6Match() != null && match.getIpv6Match().getSrcDnsName() != null) {
							ofFlow.setSrcIp(match.getIpv6Match().getSrcDnsName());
							ofFlow.setPriority(DYNAMIC_INTERNET_COMMUNICATION);
						} else {
							ofFlow.setPriority(FIXED_INTERNET_COMMUNICATION);
						}


						if (DYNAMIC_INTERNET_COMMUNICATION == ofFlow.getPriority()) {
							fromInternetDynamicFlows.add(ofFlow);
						} else {
							fromInternetStaticFlows.add(ofFlow);
						}
					}
				}
			}
		}

		DeviceMUDFlowMap deviceFlowMap = new DeviceMUDFlowMap();
		deviceFlowMap.setFromInternetDynamicFlows(fromInternetDynamicFlows);
		deviceFlowMap.setFromInternetStaticFlows(fromInternetStaticFlows);
		deviceFlowMap.setToInternetDynamicFlows(toInternetDynamicFlows);
		deviceFlowMap.setToInternetStaticFlows(toInternetStaticFlows);
		deviceFlowMap.setToLocalStaticFlows(toLocalStaticFlows);
		deviceFlowMap.setFromLocalStaticFlows(fromLocalStaticFlows);
		return deviceFlowMap;

	}

	private void installLocalNetworkRules(String deviceMac, String switchMac, DeviceMUDFlowMap deviceMUDFlowMap) {
		OFFlow ofFlow = new OFFlow();
		ofFlow.setSrcMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_ARP);
		ofFlow.setPriority(FIXED_LOCAL_COMMUNICATION);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		deviceMUDFlowMap.getToLocalStaticFlows().add(ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setDstMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_ARP);
		ofFlow.setPriority(FIXED_LOCAL_COMMUNICATION);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setDstMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.ICMP_PROTO);
		ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setDstMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.TCP_PROTO);
		ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setDstMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.UDP_PROTO);
		ofFlow.setPriority(DEFAULT_LOCAL_COMMUNICATION);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		deviceMUDFlowMap.getFromLocalStaticFlows().add(ofFlow);
	}

	private void installInternetNetworkRules(String deviceMac, String switchMac, DeviceMUDFlowMap deviceMUDFlowMap) {

		OFFlow ofFlow = new OFFlow();
		ofFlow.setSrcMac(switchMac);
		ofFlow.setDstMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.TCP_PROTO);
		ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		deviceMUDFlowMap.getFromInternetStaticFlows().add(ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setSrcMac(switchMac);
		ofFlow.setDstMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.UDP_PROTO);
		ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		deviceMUDFlowMap.getFromInternetStaticFlows().add(ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setSrcMac(deviceMac);
		ofFlow.setDstMac(switchMac);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.ICMP_PROTO);
		ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		deviceMUDFlowMap.getToInternetStaticFlows().add(ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setSrcMac(deviceMac);
		ofFlow.setDstMac(switchMac);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.UDP_PROTO);
		ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		deviceMUDFlowMap.getToInternetStaticFlows().add(ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setSrcMac(deviceMac);
		ofFlow.setDstMac(switchMac);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.TCP_PROTO);
		ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		deviceMUDFlowMap.getToInternetStaticFlows().add(ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setSrcMac(switchMac);
		ofFlow.setDstMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.ICMP_PROTO);
		ofFlow.setPriority(DEFAULT_INTERNET_COMMUNICATION);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		deviceMUDFlowMap.getFromInternetStaticFlows().add(ofFlow);

	}

	private OFFlow getMatchingFlow(SimPacket packet, List<OFFlow> ofFlows) {
		for (int i = 0; i < ofFlows.size(); i++) {
			OFFlow flow = ofFlows.get(i);
			String srcMac = packet.getSrcMac();
			String dstMac = packet.getDstMac();
			String ethType = packet.getEthType();
			String vlanId = "*";
			String srcIp = packet.getSrcIp() == null ? "*" : packet.getSrcIp();
			String dstIp = packet.getDstIp() == null ? "*" : packet.getDstIp();
			String ipProto = packet.getIpProto() == null ? "*" : packet.getIpProto();
			String srcPort = packet.getSrcPort() == null ? "*" : packet.getSrcPort();
			String dstPort = packet.getDstPort() == null ? "*" : packet.getDstPort();

			boolean condition = (srcMac.equals(flow.getSrcMac()) || flow.getSrcMac().equals("*")) &&
					(dstMac.equals(flow.getDstMac()) || flow.getDstMac().equals("*")) &&
					(ethType.equals(flow.getEthType()) || flow.getEthType().equals("*")) &&
					(vlanId.equals(flow.getVlanId()) || flow.getVlanId().equals("*")) &&
					(srcIp.equals(flow.getSrcIp()) || flow.getSrcIp().equals("*")) &&
					(dstIp.equals(flow.getDstIp()) || flow.getDstIp().equals("*")) &&
					(ipProto.equals(flow.getIpProto()) || flow.getIpProto().equals("*")) &&
					(srcPort.equals(flow.getSrcPort()) || flow.getSrcPort().equals("*")) &&
					(dstPort.equals(flow.getDstPort()) || flow.getDstPort().equals("*"));

			if (condition) {
				return flow;
			}
		}
		return null;
	}

	private List<OFFlow> sortFlowsWithPriority(List<OFFlow> flows) {

		LinkedList<OFFlow> ofFlows = new LinkedList<OFFlow>();

		for (OFFlow flow : flows) {
			boolean exist = false;
			for (int i = 0; i < ofFlows.size(); i++) {
				OFFlow currentFlow = ofFlows.get(i);
				if (currentFlow.equals(flow)) {
					exist = true;
				}
			}

			if (!exist) {
				if (ofFlows.size() == 0) {
					ofFlows.add(flow);
					continue;
				}
				for (int i = 0; i < ofFlows.size(); i++) {
					OFFlow currentFlow = ofFlows.get(i);

					if (flow.getPriority() >= currentFlow.getPriority()) {
						if (i == 0) {
							ofFlows.addFirst(flow);
							break;
						} else {
							ofFlows.add(i, flow);
							break;
						}
					} else if (i == ofFlows.size() - 1) {
						ofFlows.addLast(flow);
						break;
					}
				}

			}
		}
		return ofFlows;
	}
}
