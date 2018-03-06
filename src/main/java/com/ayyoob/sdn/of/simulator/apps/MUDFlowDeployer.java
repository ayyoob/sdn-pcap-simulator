package com.ayyoob.sdn.of.simulator.apps;

import com.ayyoob.sdn.of.simulator.Constants;
import com.ayyoob.sdn.of.simulator.OFController;
import com.ayyoob.sdn.of.simulator.OFFlow;
import com.ayyoob.sdn.of.simulator.SimPacket;
import com.ayyoob.sdn.of.simulator.apps.mudflowdto.DeviceFlowMap;
import com.ayyoob.sdn.of.simulator.processor.mud.AccessControlListHolder;
import com.ayyoob.sdn.of.simulator.processor.mud.Ace;
import com.ayyoob.sdn.of.simulator.processor.mud.Match;
import com.ayyoob.sdn.of.simulator.processor.mud.MudSpec;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.simple.JSONObject;

import java.io.File;
import java.io.IOException;
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
	private static final int D2G_DYNAMIC_FLOW_PRIORITY = 810;
	private static final int D2G_PRIORITY = 800;
	private static final int G2D_FIXED_FLOW_PRIORITY = 750;
	private static final int G2D_DYNAMIC_FLOW_PRIORITY = 710;
	private static final int G2D_PRIORITY = 700;
	private static final int L2D_FIXED_FLOW_PRIORITY = 650;
	private static final int L2D_DYNAMIC_FLOW_PRIORITY = 610;
	private static final int L2D_PRIORITY = 600;
	private static long idleTimeout = 120000;
	private static final String DEFAULTGATEWAYCONTROLLER = "urn:ietf:params:mud:gateway";
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
		ObjectMapper mapper = new ObjectMapper();
		try {
			MudSpec mudSpec = mapper.readValue(new File((String) jsonObject.get("mudPath")), MudSpec.class);
			loadMudSpec(deviceMac, mudSpec);
			installExternalNetworkRules(deviceMac);
			installInternalNetworkRules(deviceMac);

		} catch (IOException e) {
			e.printStackTrace();
		}
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
			} else if (dpId.equals(packet.getDstMac())) {
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
		String fromDevicePolicyName = mudSpec.getIetfMud().getFromDevicePolicy().getAccessList().getAccessDTOList().get(0).getName();
		String toDevicePolicyName = mudSpec.getIetfMud().getToDevicePolicy().getAccessList().getAccessDTOList().get(0).getName();
		List<OFFlow> fromDeviceFlows = new ArrayList<>();
		List<OFFlow> toDeviceFlows = new ArrayList<>();
		for (AccessControlListHolder accessControlListHolder : mudSpec.getAccessControlList().getAccessControlListHolder()) {
			if (accessControlListHolder.getName().equals(fromDevicePolicyName)) {
				for (Ace ace : accessControlListHolder.getAces().getAceList()) {
					Match match = ace.getMatches();

					//filter local
					if (match.getIetfMudMatch() != null && match.getIetfMudMatch().getController()==null) {
						//install local network related rules here
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						if(match.getL3Match() != null && match.getL3Match().getIpv4Match() != null &&
								match.getL3Match().getIpv4Match().getProtocol() != 0) {
							ofFlow.setIpProto("" + match.getL3Match().getIpv4Match().getProtocol());
						}
						//tcp
						if(match.getL4Match() != null && match.getL4Match().getTcpMatch() != null &&
								match.getL4Match().getTcpMatch().getDestinationPortMatch() != null
								&& match.getL4Match().getTcpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getL4Match().getTcpMatch().getDestinationPortMatch().getPort());
						}

						if(match.getL4Match() != null && match.getL4Match().getTcpMatch() != null &&
								match.getL4Match().getTcpMatch().getSourcePortMatch() != null
								&& match.getL4Match().getTcpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getL4Match().getTcpMatch().getSourcePortMatch().getPort());
						}
						//udp
						if(match.getL4Match() != null && match.getL4Match().getUdpMatch() != null &&
								match.getL4Match().getUdpMatch().getDestinationPortMatch() != null
								&& match.getL4Match().getUdpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getL4Match().getUdpMatch().getDestinationPortMatch().getPort());
						}

						if(match.getL4Match() != null && match.getL4Match().getUdpMatch() != null &&
								match.getL4Match().getUdpMatch().getSourcePortMatch() != null
								&& match.getL4Match().getUdpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getL4Match().getUdpMatch().getSourcePortMatch().getPort());
						}

						ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
						ofFlow.setPriority(L2D_FIXED_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						OFController.getInstance().addFlow(dpId, ofFlow);

					} else {
						boolean isDnsReply = false;
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						ofFlow.setDstMac(dpId);
						if(match.getL3Match() != null && match.getL3Match().getIpv4Match() != null &&
								match.getL3Match().getIpv4Match().getProtocol() != 0) {
							ofFlow.setIpProto("" + match.getL3Match().getIpv4Match().getProtocol());
						}
						//tcp
						if(match.getL4Match() != null && match.getL4Match().getTcpMatch() != null &&
								match.getL4Match().getTcpMatch().getDestinationPortMatch() != null
								&& match.getL4Match().getTcpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getL4Match().getTcpMatch().getDestinationPortMatch().getPort());
						}

						if(match.getL4Match() != null && match.getL4Match().getTcpMatch() != null &&
								match.getL4Match().getTcpMatch().getSourcePortMatch() != null
								&& match.getL4Match().getTcpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getL4Match().getTcpMatch().getSourcePortMatch().getPort());
						}
						//udp
						if(match.getL4Match() != null && match.getL4Match().getUdpMatch() != null &&
								match.getL4Match().getUdpMatch().getDestinationPortMatch() != null
								&& match.getL4Match().getUdpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getL4Match().getUdpMatch().getDestinationPortMatch().getPort());

						}

						if(match.getL4Match() != null && match.getL4Match().getUdpMatch() != null &&
								match.getL4Match().getUdpMatch().getSourcePortMatch() != null
								&& match.getL4Match().getUdpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getL4Match().getUdpMatch().getSourcePortMatch().getPort());
							if (ofFlow.getSrcPort().equals(Constants.DNS_PORT)) {
								isDnsReply = true;
							}
						}

						if(match.getIetfMudMatch() != null && match.getIetfMudMatch().getController()!=null &&
							match.getIetfMudMatch().getController().equals(DEFAULTGATEWAYCONTROLLER)) {
							ofFlow.setDstIp(gatewayIp);
							ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
						} else if(match.getL3Match() != null && match.getL3Match().getIpv4Match() != null &&
								match.getL3Match().getIpv4Match().getDestinationIp() != null) {
							ofFlow.setDstIp(match.getL3Match().getIpv4Match().getDestinationIp().replace("/32", ""));
							ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
						} else if(match.getL3Match() != null && match.getL3Match().getIpv4Match() != null &&
								match.getL3Match().getIpv4Match().getDstDnsName() != null) {
							ofFlow.setDstIp(match.getL3Match().getIpv4Match().getDstDnsName());
							ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
						} else {
							ofFlow.setPriority(D2G_DYNAMIC_FLOW_PRIORITY);
						}
						ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
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
			} else if (accessControlListHolder.getName().equals(toDevicePolicyName)) {

				for (Ace ace : accessControlListHolder.getAces().getAceList()) {
					Match match = ace.getMatches();

					//filter local
					if (match.getIetfMudMatch() != null && match.getIetfMudMatch().getController()==null) {
						//install local network related rules here
						OFFlow ofFlow = new OFFlow();
						ofFlow.setDstMac(deviceMac);
						if(match.getL3Match() != null && match.getL3Match().getIpv4Match() != null &&
								match.getL3Match().getIpv4Match().getProtocol() != 0) {
							ofFlow.setIpProto("" + match.getL3Match().getIpv4Match().getProtocol());
						}

						//tcp
						if(match.getL4Match() != null && match.getL4Match().getTcpMatch() != null &&
								match.getL4Match().getTcpMatch().getDestinationPortMatch() != null
								&& match.getL4Match().getTcpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getL4Match().getTcpMatch().getDestinationPortMatch().getPort());
						}

						if(match.getL4Match() != null && match.getL4Match().getTcpMatch() != null &&
								match.getL4Match().getTcpMatch().getSourcePortMatch() != null
								&& match.getL4Match().getTcpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getL4Match().getTcpMatch().getSourcePortMatch().getPort());
						}
						//udp
						if(match.getL4Match() != null && match.getL4Match().getUdpMatch() != null &&
								match.getL4Match().getUdpMatch().getDestinationPortMatch() != null
								&& match.getL4Match().getUdpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getL4Match().getUdpMatch().getDestinationPortMatch().getPort());
						}

						if(match.getL4Match() != null && match.getL4Match().getUdpMatch() != null &&
								match.getL4Match().getUdpMatch().getSourcePortMatch() != null
								&& match.getL4Match().getUdpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getL4Match().getUdpMatch().getSourcePortMatch().getPort());
						}
						ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
						ofFlow.setPriority(L2D_FIXED_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						OFController.getInstance().addFlow(dpId, ofFlow);
					} else {
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(dpId);
						ofFlow.setDstMac(deviceMac);
						if(match.getL3Match() != null && match.getL3Match().getIpv4Match() != null &&
								match.getL3Match().getIpv4Match().getProtocol() != 0) {
							ofFlow.setIpProto("" + match.getL3Match().getIpv4Match().getProtocol());
						}
						//tcp
						if(match.getL4Match() != null && match.getL4Match().getTcpMatch() != null &&
								match.getL4Match().getTcpMatch().getDestinationPortMatch() != null
								&& match.getL4Match().getTcpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getL4Match().getTcpMatch().getDestinationPortMatch().getPort());
						}

						if(match.getL4Match() != null && match.getL4Match().getTcpMatch() != null &&
								match.getL4Match().getTcpMatch().getSourcePortMatch() != null
								&& match.getL4Match().getTcpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getL4Match().getTcpMatch().getSourcePortMatch().getPort());
						}
						//udp
						if(match.getL4Match() != null && match.getL4Match().getUdpMatch() != null &&
								match.getL4Match().getUdpMatch().getDestinationPortMatch() != null
								&& match.getL4Match().getUdpMatch().getDestinationPortMatch().getPort() != 0) {
							ofFlow.setDstPort("" + match.getL4Match().getUdpMatch().getDestinationPortMatch().getPort());
						}

						if(match.getL4Match() != null && match.getL4Match().getUdpMatch() != null &&
								match.getL4Match().getUdpMatch().getSourcePortMatch() != null
								&& match.getL4Match().getUdpMatch().getSourcePortMatch().getPort() != 0) {
							ofFlow.setSrcPort("" + match.getL4Match().getUdpMatch().getSourcePortMatch().getPort());
						}

						if(match.getIetfMudMatch() != null && match.getIetfMudMatch().getController()!=null &&
								match.getIetfMudMatch().getController().equals(DEFAULTGATEWAYCONTROLLER)) {
							ofFlow.setSrcIp(gatewayIp);
							ofFlow.setPriority(G2D_DYNAMIC_FLOW_PRIORITY);
						} else if(match.getL3Match() != null && match.getL3Match().getIpv4Match() != null &&
								match.getL3Match().getIpv4Match().getSourceIp() != null) {
							ofFlow.setSrcIp(match.getL3Match().getIpv4Match().getSourceIp().replace("/32", ""));
							ofFlow.setPriority(G2D_DYNAMIC_FLOW_PRIORITY);
						} else if(match.getL3Match() != null && match.getL3Match().getIpv4Match() != null &&
								match.getL3Match().getIpv4Match().getSrcDnsName() != null) {
							ofFlow.setSrcIp(match.getL3Match().getIpv4Match().getSrcDnsName());
							ofFlow.setPriority(G2D_DYNAMIC_FLOW_PRIORITY);
						} else {
							ofFlow.setPriority(G2D_DYNAMIC_FLOW_PRIORITY);
						}
						ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
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
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
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

		ofFlow = new OFFlow();
		ofFlow.setSrcMac(dpId);
		ofFlow.setDstMac(deviceMac);
		ofFlow.setIpProto(Constants.UDP_PROTO);
		ofFlow.setSrcPort(Constants.DNS_PORT);
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setPriority(DNS_FLOW_PRIORITY);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		OFController.getInstance().addFlow(dpId, ofFlow);


//		OFFlow ofFlow = new OFFlow();
//		ofFlow.setSrcMac(dpId);
//		ofFlow.setDstMac(deviceMac);
//		ofFlow.setIpProto(Constants.TCP_PROTO);
//		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//		ofFlow.setPriority(G2D_PRIORITY);
//		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//		OFController.getInstance().addFlow(dpId, ofFlow);
//
//		ofFlow = new OFFlow();
//		ofFlow.setSrcMac(dpId);
//		ofFlow.setDstMac(deviceMac);
//		ofFlow.setIpProto(Constants.UDP_PROTO);
//		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//		ofFlow.setPriority(G2D_PRIORITY);
//		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//		OFController.getInstance().addFlow(dpId, ofFlow);
//
//		ofFlow = new OFFlow();
//		ofFlow.setSrcMac(dpId);
//		ofFlow.setDstMac(deviceMac);
//		ofFlow.setIpProto(Constants.ICMP_PROTO);
//		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//		ofFlow.setPriority(G2D_PRIORITY);
//		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//		OFController.getInstance().addFlow(dpId, ofFlow);
//
//
//		ofFlow = new OFFlow();
//		ofFlow.setSrcMac(deviceMac);
//		ofFlow.setDstMac(dpId);
//		ofFlow.setIpProto(Constants.ICMP_PROTO);
//		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//		ofFlow.setPriority(D2G_PRIORITY);
//		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//		OFController.getInstance().addFlow(dpId, ofFlow);
//
//
//		ofFlow = new OFFlow();
//		ofFlow.setSrcMac(deviceMac);
//		ofFlow.setDstMac(dpId);
//		ofFlow.setIpProto(Constants.TCP_PROTO);
//		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//		ofFlow.setPriority(D2G_PRIORITY);
//		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//		OFController.getInstance().addFlow(dpId, ofFlow);
//
//		ofFlow = new OFFlow();
//		ofFlow.setSrcMac(deviceMac);
//		ofFlow.setDstMac(dpId);
//		ofFlow.setIpProto(Constants.UDP_PROTO);
//		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
//		ofFlow.setPriority(D2G_PRIORITY);
//		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
//		OFController.getInstance().addFlow(dpId, ofFlow);
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
}
