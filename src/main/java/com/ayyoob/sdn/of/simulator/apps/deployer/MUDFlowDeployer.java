package com.ayyoob.sdn.of.simulator.apps.deployer;

import com.ayyoob.sdn.of.simulator.Constants;
import com.ayyoob.sdn.of.simulator.OFController;
import com.ayyoob.sdn.of.simulator.OFFlow;
import com.ayyoob.sdn.of.simulator.SimPacket;
import com.ayyoob.sdn.of.simulator.apps.ControllerApp;
import com.ayyoob.sdn.of.simulator.apps.deployer.mudflowdto.DeviceFlowMap;
import com.ayyoob.sdn.of.simulator.apps.legacydevice.processor.mud.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.simple.JSONObject;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MUDFlowDeployer implements ControllerApp {
	private static boolean enabled = true;
	private static String deviceMac;
	private static String gatewayIp;
	private static String dpId;
	private static final int DNS_FLOW_PRIORITY = 1100;
	private static final int D2G_FIXED_FLOW_PRIORITY = 850;
	private static final int COMMON_EAPOL_FLOW_PRIORITY = 1200;

	private static final int D2G_DYNAMIC_FLOW_PRIORITY = 810;
	private static final int D2G_PRIORITY = 800;
	private static final int G2D_FIXED_FLOW_PRIORITY = 750;
	private static final int G2D_DYNAMIC_FLOW_PRIORITY = 710;
	private static final int G2D_PRIORITY = 700;
	private static final int GW_PRIORITY = 1050;
	private static final int L2D_FIXED_FLOW_PRIORITY = 650;
	private static final int L2D_DYNAMIC_FLOW_PRIORITY = 610;
	private static final int L2D_PRIORITY = 600;
	private static long idleTimeout = 120000;
	private static final String DEFAULTGATEWAYCONTROLLER = "urn:ietf:params:mud:gateway";
	private static final String DEFAULT_DNS_CONTROLLER = "urn:ietf:params:mud:dns";
	private static final String DEFAULT_NTP_CONTROLLER = "urn:ietf:params:mud:ntp";
	Map<String, DeviceFlowMap> deviceFlowMapHolder = new HashMap<>();

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
				MudSpec mudSpec = mapper.readValue(new File(path), MudSpec.class);
				loadMudSpec(dmac, mudSpec);
				installExternalNetworkRules(dmac);
				installInternalNetworkRules(dmac);

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		List<String> ips1 = new ArrayList<>();
		ips1.add("54.196.197.46");
		ips1.add("54.81.152.49");
		ips1.add("54.87.58.52");
		ips1.add("54.198.33.220");
		ips1.add("54.162.197.42");
		ips1.add("54.198.241.119");
		ips1.add("174.129.217.97");
		deviceFlowMapHolder.get(deviceMac).addDnsIps("tunnel.xbcs.net", ips1);

		List<String> ips2 = new ArrayList<>();
		ips2.add("52.52.47.66");
		ips2.add("52.9.13.36");
		deviceFlowMapHolder.get(deviceMac).addDnsIps("xmpp.samsungsmartcam.com", ips2);

		OFFlow ofFlow = new OFFlow();
		ofFlow.setEthType(Constants.ETH_TYPE_EAPOL);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		ofFlow.setPriority(COMMON_EAPOL_FLOW_PRIORITY);
		OFController.getInstance().addFlow(dpId, ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setDstMac(Constants.BROADCAST_MAC);
		ofFlow.setDstPort(Constants.DHCP_PORT);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		ofFlow.setPriority(COMMON_EAPOL_FLOW_PRIORITY);
		OFController.getInstance().addFlow(dpId, ofFlow);
	}

	@Override
	public void process(String dpId, SimPacket packet) {
		if (!enabled) {
			return;
		}
		if (packet.getDnsAnswers() != null) {
			deviceFlowMapHolder.get(packet.getDstMac()).addDnsIps(packet.getdnsQname(), packet.getDnsAnswers());
		} else {
			if (dpId.equals(packet.getSrcMac())) {
				//G2D
				String deviceMac = packet.getDstMac();
				DeviceFlowMap deviceFlowMap = deviceFlowMapHolder.get(deviceMac);
				String dns = deviceFlowMap.getDns(packet.getSrcIp());
				String srcIp = packet.getSrcIp();
				if (dns != null) {
					packet.setSrcIp(dns);
				}
				List<OFFlow> ofFlows = deviceFlowMap.getToDeviceFlows();
				OFFlow ofFlow = getMatchingFlow(packet, ofFlows);
				if (ofFlow != null) {
					ofFlow = ofFlow.copy();
					ofFlow.setIdleTimeOut(idleTimeout);
					if (ofFlow.getSrcIp().equals(dns)) {
						ofFlow.setSrcIp(srcIp);
					}
					OFController.getInstance().addFlow(dpId, ofFlow);
					return;
				}
			} else if (dpId.equals(packet.getDstMac()) || isMulticastorBroadcast(packet.getDstMac())) {
				//D2G

				String deviceMac = packet.getSrcMac();
				DeviceFlowMap deviceFlowMap = deviceFlowMapHolder.get(deviceMac);
				String dns = deviceFlowMap.getDns(packet.getDstIp());
				String dstIp = packet.getDstIp();
				if (dns != null) {
					packet.setDstIp(dns);
				}
				List<OFFlow> ofFlows = deviceFlowMap.getFromDeviceFlows();
				OFFlow ofFlow = getMatchingFlow(packet, ofFlows);
				if (ofFlow != null) {
					ofFlow = ofFlow.copy();
					ofFlow.setIdleTimeOut(idleTimeout);
					if (ofFlow.getDstIp().equals(dns)) {
						ofFlow.setDstIp(dstIp);
					}
					OFController.getInstance().addFlow(dpId, ofFlow);
					return;
				}
			}
		}


	}

	@Override
	public void complete() {

	}

	private void loadMudSpec(String deviceMac, MudSpec mudSpec) {
		List<String> fromDevicePolicyNames = new ArrayList<>();
		List<String> toDevicePolicyNames = new ArrayList<>();
		for (AccessDTO accessDTO : mudSpec.getIetfMud().getFromDevicePolicy().getAccessList().getAccessDTOList()) {
			fromDevicePolicyNames.add(accessDTO.getName());
		}

		for (AccessDTO accessDTO : mudSpec.getIetfMud().getToDevicePolicy().getAccessList().getAccessDTOList()) {
			toDevicePolicyNames.add(accessDTO.getName());
		}

		List<OFFlow> fromDeviceFlows = new ArrayList<>();
		List<OFFlow> toDeviceFlows = new ArrayList<>();
		for (AccessControlListHolder accessControlListHolder : mudSpec.getAccessControlList().getAccessControlListHolder()) {
			if (fromDevicePolicyNames.contains(accessControlListHolder.getName())) {
				for (Ace ace : accessControlListHolder.getAces().getAceList()) {
					Match match = ace.getMatches();

					//filter local
					if (match.getIetfMudMatch() != null && match.getIetfMudMatch().getController()==null
							&& match.getIetfMudMatch().getLocalNetworks() != null) {

						//install local network related rules here
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
								.getEtherType();
						ofFlow.setEthType(etherType);
						if(match.getIpv4Match() != null &&
								match.getIpv4Match().getProtocol() != 0) {

							ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
							ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
						}

						if(match.getIpv6Match() != null) {
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
						if( match.getTcpMatch() != null &&
								match.getTcpMatch().getDestinationPortMatch() != null
								&& match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
						}

						if(match != null && match.getTcpMatch() != null &&
								match.getTcpMatch().getSourcePortMatch() != null
								&& match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
						}
						//udp
						if(match != null && match.getUdpMatch() != null &&
								match.getUdpMatch().getDestinationPortMatch() != null
								&& match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
						}

						if(match != null && match.getUdpMatch() != null &&
								match.getUdpMatch().getSourcePortMatch() != null
								&& match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
						}

						if ((match.getIpv4Match() != null && match.getIpv4Match().getDestinationIp() != null)) {
							ofFlow.setDstIp(match.getIpv4Match().getDestinationIp().replace("/32", ""));
						} else if (match.getIpv6Match() != null && match.getIpv6Match().getDestinationIp() != null) {
							if (match.getIpv6Match().getDestinationIp().equals(Constants.LINK_LOCAL_MULTICAST_IP_RANGE)) {
								ofFlow.setDstIp("*");
							} else {
								ofFlow.setDstIp(match.getIpv6Match().getDestinationIp().replace("/32", ""));
							}
						}
						ofFlow.setPriority(L2D_FIXED_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						OFController.getInstance().addFlow(dpId, ofFlow);

					} else {
						boolean isDnsReply = false;
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						ofFlow.setDstMac(dpId);

						String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
								.getEtherType();
						ofFlow.setEthType(etherType);
						if(match.getIpv4Match() != null &&
								match.getIpv4Match().getProtocol() != 0) {
							ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
							ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
						}

						if(match.getIpv6Match() != null) {
							ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
							ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
						}

						//tcp
						if(match != null && match.getTcpMatch() != null &&
								match.getTcpMatch().getDestinationPortMatch() != null
								&& match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
						}

						if(match != null && match.getTcpMatch() != null &&
								match.getTcpMatch().getSourcePortMatch() != null
								&& match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
						}
						//udp
						if(match != null && match.getUdpMatch() != null &&
								match.getUdpMatch().getDestinationPortMatch() != null
								&& match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());

						}

						if(match != null && match.getUdpMatch() != null &&
								match.getUdpMatch().getSourcePortMatch() != null
								&& match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
							if (ofFlow.getSrcPort().equals(Constants.DNS_PORT)) {
								isDnsReply = true;
							}
						}

						if(match.getIetfMudMatch() != null && match.getIetfMudMatch().getController()!=null &&
								(match.getIetfMudMatch().getController().equals(DEFAULTGATEWAYCONTROLLER)
										|| match.getIetfMudMatch().getController().equals(DEFAULT_DNS_CONTROLLER)
										|| match.getIetfMudMatch().getController().equals(DEFAULT_NTP_CONTROLLER))) {
							ofFlow.setDstIp(gatewayIp);
							ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
						} else if(match != null && match.getIpv4Match() != null &&
								match.getIpv4Match().getDestinationIp() != null) {
							ofFlow.setDstIp(match.getIpv4Match().getDestinationIp().replace("/32", ""));
							ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
						} else if(match != null && match.getIpv4Match() != null &&
								match.getIpv4Match().getDstDnsName() != null) {
							ofFlow.setDstIp(match.getIpv4Match().getDstDnsName());
							ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
						} else if(match != null && match.getIpv6Match() != null &&
								match.getIpv6Match().getDestinationIp() != null) {
							ofFlow.setDstIp(match.getIpv6Match().getDestinationIp().replace("/32", ""));
							ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
						} else if(match != null && match.getIpv6Match() != null &&
								match.getIpv6Match().getDstDnsName() != null) {
							ofFlow.setDstIp(match.getIpv6Match().getDstDnsName());
							ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
						} else {
							ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
						}
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						if (!isDnsReply) {
							if (D2G_DYNAMIC_FLOW_PRIORITY == ofFlow.getPriority()) {
								fromDeviceFlows.add(ofFlow);
							} else {
								OFController.getInstance().addFlow(dpId, ofFlow);
							}
						}

					}
				}
			} else if (toDevicePolicyNames.contains(accessControlListHolder.getName())) {

				for (Ace ace : accessControlListHolder.getAces().getAceList()) {
					Match match = ace.getMatches();

					//filter local
					if (match.getIetfMudMatch() != null && match.getIetfMudMatch().getController()==null
							&& match.getIetfMudMatch().getLocalNetworks() != null) {
						//install local network related rules here
						OFFlow ofFlow = new OFFlow();
						ofFlow.setDstMac(deviceMac);
						if(match != null && match.getIpv4Match() != null &&
								match.getIpv4Match().getProtocol() != 0) {
							ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
							ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
						}

						if(match.getIpv6Match() != null) {
							ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
							ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
						}

						//tcp
						if(match != null && match.getTcpMatch() != null &&
								match.getTcpMatch().getDestinationPortMatch() != null
								&& match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
						}

						if(match != null && match.getTcpMatch() != null &&
								match.getTcpMatch().getSourcePortMatch() != null
								&& match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
						}
						//udp
						if(match != null && match.getUdpMatch() != null &&
								match.getUdpMatch().getDestinationPortMatch() != null
								&& match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
						}

						if(match != null && match.getUdpMatch() != null &&
								match.getUdpMatch().getSourcePortMatch() != null
								&& match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
						}
						ofFlow.setPriority(L2D_FIXED_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						OFController.getInstance().addFlow(dpId, ofFlow);
					} else {
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(dpId);
						ofFlow.setDstMac(deviceMac);
						String etherType = match.getEthMatch() == null ? Constants.ETH_TYPE_IPV4 : match.getEthMatch()
								.getEtherType();
						ofFlow.setEthType(etherType);
						if(match.getIpv4Match() != null &&
								match.getIpv4Match().getProtocol() != 0) {

							ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
							ofFlow.setIpProto("" + match.getIpv4Match().getProtocol());
						}

						if(match.getIpv6Match() != null) {
							ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
							ofFlow.setIpProto("" + match.getIpv6Match().getProtocol());
						}

						//tcp
						if(match != null && match.getTcpMatch() != null &&
								match.getTcpMatch().getDestinationPortMatch() != null
								&& match.getTcpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getTcpMatch().getDestinationPortMatch().getPort());
						}

						if(match != null && match.getTcpMatch() != null &&
								match.getTcpMatch().getSourcePortMatch() != null
								&& match.getTcpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getTcpMatch().getSourcePortMatch().getPort());
						}
						//udp
						if(match != null && match.getUdpMatch() != null &&
								match.getUdpMatch().getDestinationPortMatch() != null
								&& match.getUdpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getUdpMatch().getDestinationPortMatch().getPort());
						}

						if(match != null && match.getUdpMatch() != null &&
								match.getUdpMatch().getSourcePortMatch() != null
								&& match.getUdpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getUdpMatch().getSourcePortMatch().getPort());
						}

						if(match.getIetfMudMatch() != null && match.getIetfMudMatch().getController()!=null &&
								(match.getIetfMudMatch().getController().equals(DEFAULTGATEWAYCONTROLLER)
										|| match.getIetfMudMatch().getController().equals(DEFAULT_DNS_CONTROLLER)
										|| match.getIetfMudMatch().getController().equals(DEFAULT_NTP_CONTROLLER))) {
							ofFlow.setSrcIp(gatewayIp);
							ofFlow.setPriority(G2D_DYNAMIC_FLOW_PRIORITY);
						} else if(match != null && match.getIpv4Match() != null &&
								match.getIpv4Match().getSourceIp() != null) {
							ofFlow.setSrcIp(match.getIpv4Match().getSourceIp().replace("/32", ""));
							ofFlow.setPriority(G2D_DYNAMIC_FLOW_PRIORITY);
						} else if(match != null && match.getIpv4Match() != null &&
								match.getIpv4Match().getSrcDnsName() != null) {
							ofFlow.setSrcIp(match.getIpv4Match().getSrcDnsName());
							ofFlow.setPriority(G2D_DYNAMIC_FLOW_PRIORITY);
						} else if(match != null && match.getIpv6Match() != null &&
								match.getIpv6Match().getSourceIp() != null) {
							ofFlow.setSrcIp(match.getIpv6Match().getSourceIp().replace("/32", ""));
							ofFlow.setPriority(G2D_DYNAMIC_FLOW_PRIORITY);
						} else if(match != null && match.getIpv6Match() != null &&
								match.getIpv6Match().getSrcDnsName() != null) {
							ofFlow.setSrcIp(match.getIpv6Match().getSrcDnsName());
							ofFlow.setPriority(G2D_DYNAMIC_FLOW_PRIORITY);
						} else {
							ofFlow.setPriority(G2D_DYNAMIC_FLOW_PRIORITY);
						}

						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						if (G2D_DYNAMIC_FLOW_PRIORITY == ofFlow.getPriority()) {
							toDeviceFlows.add(ofFlow);
						} else {
							OFController.getInstance().addFlow(dpId, ofFlow);
						}
					}
				}
			}
		}

		DeviceFlowMap deviceFlowMap = new DeviceFlowMap();
		deviceFlowMap.setFromDeviceFlows(fromDeviceFlows);
		deviceFlowMap.setToDeviceFlows(toDeviceFlows);
		deviceFlowMapHolder.put(deviceMac, deviceFlowMap);
		OFController.getInstance().getSwitch(dpId).printFlows();

	}

	private void installInternalNetworkRules(String deviceMac) {
		OFFlow ofFlow = new OFFlow();
		ofFlow.setSrcMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_ARP);
		ofFlow.setPriority(L2D_PRIORITY + 20);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		OFController.getInstance().addFlow(dpId, ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setDstMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_ARP);
		ofFlow.setPriority(L2D_PRIORITY + 20);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		OFController.getInstance().addFlow(dpId, ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setDstMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setPriority(L2D_PRIORITY);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		OFController.getInstance().addFlow(dpId, ofFlow);

//		OFFlow ofFlow = new OFFlow();
//		ofFlow.setSrcMac(deviceMac);
//		ofFlow.setEthType(Constants.ETH_TYPE_ARP);
//		ofFlow.setPriority(L2D_PRIORITY + 20);
//		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
//		OFController.getInstance().addFlow(dpId, ofFlow);
//
//		ofFlow = new OFFlow();
//		ofFlow.setDstMac(deviceMac);
//		ofFlow.setEthType(Constants.ETH_TYPE_ARP);
//		ofFlow.setPriority(L2D_PRIORITY + 20);
//		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
//		OFController.getInstance().addFlow(dpId, ofFlow);
//
//		ofFlow = new OFFlow();
//		ofFlow.setDstMac(deviceMac);
//		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//		ofFlow.setPriority(L2D_PRIORITY);
//		ofFlow.setIpProto(Constants.TCP_PROTO);
//		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
//		OFController.getInstance().addFlow(dpId, ofFlow);
//
//		ofFlow = new OFFlow();
//		ofFlow.setDstMac(deviceMac);
//		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//		ofFlow.setPriority(L2D_PRIORITY);
//		ofFlow.setIpProto(Constants.UDP_PROTO);
//		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
//		OFController.getInstance().addFlow(dpId, ofFlow);
//
//		ofFlow = new OFFlow();
//		ofFlow.setDstMac(deviceMac);
//		ofFlow.setIpProto(Constants.ICMP_PROTO);
//		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//		ofFlow.setPriority(L2D_PRIORITY + 1);
//		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
//		OFController.getInstance().addFlow(dpId, ofFlow);
	}

	private void installExternalNetworkRules(String deviceMac) {

		OFFlow ofFlow = new OFFlow();
		ofFlow.setSrcMac(dpId);
		ofFlow.setDstMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setPriority(G2D_PRIORITY);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		OFController.getInstance().addFlow(dpId, ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setSrcMac(deviceMac);
		ofFlow.setDstMac(dpId);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setPriority(D2G_PRIORITY);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		OFController.getInstance().addFlow(dpId, ofFlow);

		//Gateway communication
		ofFlow = new OFFlow();
		ofFlow.setSrcMac(dpId);
		ofFlow.setDstMac(deviceMac);
		ofFlow.setSrcIp(gatewayIp);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setPriority(GW_PRIORITY);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		OFController.getInstance().addFlow(dpId, ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setSrcMac(deviceMac);
		ofFlow.setDstMac(dpId);
		ofFlow.setDstIp(gatewayIp);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setPriority(GW_PRIORITY);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		OFController.getInstance().addFlow(dpId, ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setSrcMac(dpId);
		ofFlow.setDstMac(deviceMac);
		ofFlow.setSrcIp("fe80:0:0:0:16cc:20ff:fe51:33ea");
		ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
		ofFlow.setPriority(GW_PRIORITY);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		OFController.getInstance().addFlow(dpId, ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setSrcMac(deviceMac);
		ofFlow.setDstMac(dpId);
		ofFlow.setDstIp("fe80:0:0:0:16cc:20ff:fe51:33ea");
		ofFlow.setEthType(Constants.ETH_TYPE_IPV6);
		ofFlow.setPriority(GW_PRIORITY);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		OFController.getInstance().addFlow(dpId, ofFlow);




		ofFlow = new OFFlow();
		ofFlow.setSrcMac(dpId);
		ofFlow.setDstMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.ICMP_PROTO);
		ofFlow.setPriority(G2D_DYNAMIC_FLOW_PRIORITY);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		OFController.getInstance().addFlow(dpId, ofFlow);


		ofFlow = new OFFlow();
		ofFlow.setSrcMac(dpId);
		ofFlow.setDstMac(deviceMac);
		ofFlow.setIpProto(Constants.UDP_PROTO);
		ofFlow.setSrcPort(Constants.DNS_PORT);
		//ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setPriority(DNS_FLOW_PRIORITY);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		OFController.getInstance().addFlow(dpId, ofFlow);
	}

	private OFFlow getMatchingFlow(SimPacket packet, List<OFFlow> ofFlows) {
		for (int i = 0 ; i < ofFlows.size(); i++) {
			OFFlow flow = ofFlows.get(i);
			String srcMac=packet.getSrcMac();
			String dstMac=packet.getDstMac();
			String ethType=packet.getEthType();
			String vlanId="*";
			String srcIp=packet.getSrcIp() == null ? "*": packet.getSrcIp();
			String dstIp=packet.getDstIp() == null ? "*": packet.getDstIp();
			String ipProto=packet.getIpProto()== null ? "*": packet.getIpProto();
			String srcPort=packet.getSrcPort()== null ? "*": packet.getSrcPort();
			String dstPort=packet.getDstPort()== null ? "*": packet.getDstPort();

			boolean condition = (srcMac.equals(flow.getSrcMac()) || flow.getSrcMac().equals("*"))&&
					(dstMac.equals(flow.getDstMac())  || flow.getDstMac().equals("*"))&&
					(ethType.equals(flow.getEthType()) || flow.getEthType().equals("*")) &&
					(vlanId.equals(flow.getVlanId())  || flow.getVlanId().equals("*"))&&
					(srcIp.equals(flow.getSrcIp())  || flow.getSrcIp().equals("*"))&&
					(dstIp.equals(flow.getDstIp())  || flow.getDstIp().equals("*"))&&
					(ipProto.equals(flow.getIpProto())  || flow.getIpProto().equals("*"))&&
					(srcPort.equals(flow.getSrcPort())  || flow.getSrcPort().equals("*"))&&
					(dstPort.equals(flow.getDstPort()) || flow.getDstPort().equals("*"));

			if (condition) {
				return flow;
			}
		}
		return null;
	}

	private boolean isMulticastorBroadcast(String mac) {
		if (mac.length() == Constants.BROADCAST_MAC.length()) {
			String mostSignificantByte = mac.split(":")[0];
			String binary = new BigInteger(mostSignificantByte, 16).toString(2);
			if (mac.equals(Constants.BROADCAST_MAC) || binary.charAt(binary.length() -1) == '1') {
				return true;
			}
		}
		return false;
	}
}
