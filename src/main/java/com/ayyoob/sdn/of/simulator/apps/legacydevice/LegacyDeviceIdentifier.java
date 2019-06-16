package com.ayyoob.sdn.of.simulator.apps.legacydevice;

import com.ayyoob.sdn.of.simulator.Constants;
import com.ayyoob.sdn.of.simulator.OFController;
import com.ayyoob.sdn.of.simulator.OFFlow;
import com.ayyoob.sdn.of.simulator.SimPacket;
import com.ayyoob.sdn.of.simulator.apps.ControllerApp;
import org.json.simple.JSONObject;

import java.math.BigInteger;
import java.util.*;

public class LegacyDeviceIdentifier implements ControllerApp {

	private boolean enabled = true;
	private String deviceMac;
	private String gatewayIp;
	private String gatewayIpv6;
	private String dpId;
	private static long idleTimeout = 120000;
	private static final int COMMON_SKIP_FLOW_PRIORITY = 5;
	private static final int REACTIVE_INTERNET_FLOW_PRIORITY = 10;
	private static final int REACTIVE_LOCAL_FLOW_PRIORITY = 9;
	private Map<String, List<String>> dnsIpMap = new HashMap<>();
	private static int MAXIP_PER_DNS = 150;
	private static String WILDCARD = "*";
	public static DeviceNode deviceNode;
	public static final String DEFAULT_GATEWAY_CONTROLLER = "urn:ietf:params:mud:gateway";
	private static final String DEFAULT_DNS_CONTROLLER = "urn:ietf:params:mud:dns";
	private static final String DEFAULT_NTP_CONTROLLER = "urn:ietf:params:mud:ntp";
	public static int packetCounter = 0;
	private static final int EDGE_LIMIT = 200;
	//todo workaround
	String ipList[] = {"10.", "172.16.", "192.168.", "100."};

	@Override
	public void init(JSONObject jsonObject) {

		enabled = (Boolean) jsonObject.get("enable");
		idleTimeout = ((Long) jsonObject.get("idleTimeoutInSeconds")) * 1000L;
		if (!enabled) {
			return;
		}
		deviceMac = (String) jsonObject.get("deviceMac");


		gatewayIp = (String) jsonObject.get("gatewayIp");
		gatewayIpv6 = (String) jsonObject.get("gatewayIpv6");
		dpId = (String) jsonObject.get("dpId");


		OFFlow ofFlow = new OFFlow();
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.ICMP_PROTO);
		ofFlow.setSrcMac(dpId);
		ofFlow.setSrcIp(gatewayIp);
		ofFlow.setDstMac(deviceMac);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		ofFlow.setPriority(COMMON_SKIP_FLOW_PRIORITY +2);
		OFController.getInstance().addFlow(dpId, ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.ICMP_PROTO);
		ofFlow.setSrcMac(dpId);
		ofFlow.setDstMac(deviceMac);
		ofFlow.setOfAction(OFFlow.OFAction.MIRROR_TO_CONTROLLER);
		ofFlow.setIcmpCode("0");
		ofFlow.setIcmpCode("0");
		ofFlow.setPriority(COMMON_SKIP_FLOW_PRIORITY + 1);
		OFController.getInstance().addFlow(dpId, ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setEthType(Constants.ETH_TYPE_IPV4);
		ofFlow.setIpProto(Constants.ICMP_PROTO);
		ofFlow.setSrcMac(dpId);
		ofFlow.setDstMac(deviceMac);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		ofFlow.setPriority(COMMON_SKIP_FLOW_PRIORITY);
		OFController.getInstance().addFlow(dpId, ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setSrcMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_ARP);
		ofFlow.setPriority(COMMON_SKIP_FLOW_PRIORITY);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		OFController.getInstance().addFlow(dpId, ofFlow);

		ofFlow = new OFFlow();
		ofFlow.setDstMac(deviceMac);
		ofFlow.setEthType(Constants.ETH_TYPE_ARP);
		ofFlow.setPriority(COMMON_SKIP_FLOW_PRIORITY);
		ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
		OFController.getInstance().addFlow(dpId, ofFlow);

		deviceNode = new DeviceNode(deviceMac);
	}

	public void addDnsIps(String dns, List<String> ips) {
//		latestDNS.addFirst(dns);
//		if (latestDNS.size() > MAX_DNS) {
//			latestDNS.removeLast();
//		}
		if (dnsIpMap.get(dns) == null) {
			dnsIpMap.put(dns, ips);
		} else {
			List<String> ipholder = dnsIpMap.get(dns);
			if (ipholder.size() + ips.size() > MAXIP_PER_DNS) {
				int toRemove = MAXIP_PER_DNS - (ipholder.size() + ips.size());
				if (toRemove > 0) {
					for (int i = 0; i < toRemove; i++) {
						ipholder.remove(0);
					}
				}
			}
			ipholder.addAll(ips);
			dnsIpMap.put(dns, ipholder);
		}
	}

	public List<String> getDns(String ip) {

//		for (String dns : latestDNS) {
//			if (dnsIpMap.get(dns).contains(ip)) {
//				return dns;
//			}
//		}
		List<String> dnsList = new ArrayList<>();

		for (String dns : dnsIpMap.keySet()) {
			if (dnsIpMap.get(dns).contains(ip)) {
				dnsList.add(dns);
			}
		}
		if (dnsList.isEmpty()) {
			dnsList.add(ip);
			return dnsList;
		}
		return dnsList;
	}

	public String getControllerMapping(String ip, String port, String mac) {
		if (gatewayIp.equals(ip) || gatewayIpv6.equals(ip) || gatewayIpv6.replace("0.0.0", "").equals(ip)) {
			if (port.equals(Constants.DNS_PORT)) {
				return DEFAULT_DNS_CONTROLLER;
			} else if (port.equals(Constants.NTP_PORT)) {
				return DEFAULT_NTP_CONTROLLER;
			} else {
				return DEFAULT_GATEWAY_CONTROLLER;
			}
		} else if (ip.equals("0.0.0.0")) {
			return Constants.BROADCAST_MAC;
		} else if (isMulticastorBroadcast(mac)) {
			if (ip.startsWith("ff02")) {
				return "ff00::/8";
			} else if (ip.startsWith("192.168.1.255")) {
				return mac;
			}
			return ip;
		}
		return WILDCARD;
	}

	@Override
	public void process(String switchMac, SimPacket packet) {
		//skip redirection packets
		if (packet.getIcmpCode() != null && (packet.getIcmpType().equals("3") || packet.getIcmpType().equals("11")
				|| packet.getIcmpType().equals("5"))) {
			return;
		}
		packetCounter ++;
		if (packet.getDnsAnswers() != null && packet.getDstMac().equals(deviceMac)) {
			addDnsIps(packet.getdnsQname(), packet.getDnsAnswers());

		}
		if (packet.getSrcMac().equals(deviceMac) && packet.getDstPort()!=null && packet.getDstPort().equals("1900")) {
			deviceNode.setSupportsSsdp(true);
		}
		String endpoint = WILDCARD;
		//FromInternet //todo
		if (packet.getSrcMac().equals(switchMac) && packet.getDstMac().equals(deviceMac)
				 && packet.getSrcIp() != null && !packet.getSrcIp().equals(gatewayIp) && !packet.getSrcIp().equals(gatewayIpv6)) {
			endpoint = packet.getSrcIp();
			List<String> endpoints = getDns(endpoint);
			//tcp
			if ((packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) &&
					packet.getIpProto().equals(Constants.TCP_PROTO)) {
				if (packet.getTcpFlag() == SimPacket.Flag.SYN) {
					EdgeNode edgeNode = new EdgeNode();
					edgeNode.setDestPort(Integer.parseInt(packet.getDstPort()));
					edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
					edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2),16));

					boolean flowAdded =false;
					for (String dnsEndpoint : endpoints) {
						EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.FROM_INTERNET, dnsEndpoint, edgeNode);
						if (retreivedNode == null) {

							//attack rate limit.
							int edgeLimit = 0;
							EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_INTERNET
									, dnsEndpoint);
							if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
								for (EdgeNode ex : edd.getEdges()) {
									if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
										edgeLimit++;
									}
								}
							}
							if (edgeLimit < EDGE_LIMIT) {
								deviceNode.addNode(DeviceNode.Directions.FROM_INTERNET, dnsEndpoint, edgeNode);
							}

							if (!flowAdded) {
								OFFlow ofFlow = new OFFlow();
								ofFlow.setSrcMac(switchMac);
								ofFlow.setDstMac(deviceMac);
								ofFlow.setSrcIp(packet.getSrcIp());
								if (edgeLimit < EDGE_LIMIT) {
									ofFlow.setDstPort(packet.getDstPort());
								}
								ofFlow.setEthType(packet.getEthType());
								ofFlow.setIpProto(packet.getIpProto());
								ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
								ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
								ofFlow.setIdleTimeOut(idleTimeout);
								OFController.getInstance().addFlow(dpId, ofFlow);
								flowAdded = true;
							}


						} else if (!flowAdded) {
							OFFlow ofFlow = new OFFlow();
							ofFlow.setSrcMac(switchMac);
							ofFlow.setDstMac(deviceMac);
							ofFlow.setSrcIp(retreivedNode.getValue().equals(dnsEndpoint) ? packet.getSrcIp() :
									retreivedNode.getValue().equals("*") ? "*": packet.getSrcIp());
							ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
							boolean singleSourcePortValue = retreivedNode.getEdges().get(0).getSourcePortStart()
									== retreivedNode.getEdges().get(0).getSourcePortEnd();
							boolean singleDestPortValue = retreivedNode.getEdges().get(0).getDestPortStart()
									== retreivedNode.getEdges().get(0).getDestPortEnd();

							if (singleSourcePortValue) {
								ofFlow.setSrcPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getSourcePortEnd()));
							}

							if (singleDestPortValue) {
								ofFlow.setDstPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getDestPortEnd()));
							}

							if (!singleDestPortValue && !singleSourcePortValue) {
								ofFlow.setDstPort(packet.getDstPort());
								ofFlow.setSrcPort(packet.getSrcPort());
							}

							//attack rate limit.
							int edgeLimit = 0;
							EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_INTERNET
									, retreivedNode.getValue());
							if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
								for (EdgeNode ex : edd.getEdges()) {
									if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
										edgeLimit++;
									}
								}
							}
							if (edgeLimit >= EDGE_LIMIT) {
								ofFlow.setDstPort("*");
								ofFlow.setSrcPort("*");
							}


							ofFlow.setEthType(packet.getEthType());
							ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
							ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
							ofFlow.setIdleTimeOut(idleTimeout);
							OFController.getInstance().addFlow(dpId, ofFlow);
							flowAdded = true;
						}
					}

				} else if (packet.getTcpFlag() == SimPacket.Flag.SYN_ACK) {

					EdgeNode edgeNode = new EdgeNode();
					edgeNode.setSourcePort(Integer.parseInt(packet.getSrcPort()));
					edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
					edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2),16));
					boolean flowAdded =false;
					for (String dnsEndpoint : endpoints) {
						EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.FROM_INTERNET, dnsEndpoint, edgeNode);
						if (retreivedNode == null) {

							int edgeLimit = 0;
							EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_INTERNET
									, dnsEndpoint);
							if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
								for (EdgeNode ex : edd.getEdges()) {
									if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
										edgeLimit++;
									}
								}
							}
							if (edgeLimit < EDGE_LIMIT) {
								deviceNode.addNode(DeviceNode.Directions.FROM_INTERNET, dnsEndpoint, edgeNode);
							}

							OFFlow ofFlow = new OFFlow();
							ofFlow.setSrcMac(switchMac);
							ofFlow.setDstMac(deviceMac);
							ofFlow.setSrcIp(packet.getSrcIp());
							if (edgeLimit < EDGE_LIMIT) {
								ofFlow.setSrcPort(packet.getSrcPort());
							}
							ofFlow.setEthType(packet.getEthType());
							ofFlow.setIpProto(packet.getIpProto());
							ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
							ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
							ofFlow.setIdleTimeOut(idleTimeout);
							if (!flowAdded) {
								OFController.getInstance().addFlow(dpId, ofFlow);
								flowAdded =true;
							}

						} else if(!flowAdded) {
							OFFlow ofFlow = new OFFlow();
							ofFlow.setSrcMac(switchMac);
							ofFlow.setDstMac(deviceMac);


							ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
							boolean singleSourcePortValue = retreivedNode.getEdges().get(0).getSourcePortStart()
									== retreivedNode.getEdges().get(0).getSourcePortEnd();
							boolean singleDestPortValue = retreivedNode.getEdges().get(0).getDestPortStart()
									== retreivedNode.getEdges().get(0).getDestPortEnd();

							if (singleSourcePortValue) {
								ofFlow.setSrcPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getSourcePortEnd()));
							}

							if (singleDestPortValue) {
								ofFlow.setDstPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getDestPortEnd()));
							}

							if (!singleDestPortValue && !singleSourcePortValue) {
								ofFlow.setDstPort(packet.getDstPort());
								ofFlow.setSrcPort(packet.getSrcPort());
							}

							//attack rate limit.
							int edgeLimit = 0;
							EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_INTERNET
									, retreivedNode.getValue());
							if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
								for (EdgeNode ex : edd.getEdges()) {
									if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
										edgeLimit++;
									}
								}
							}
							if (edgeLimit >= EDGE_LIMIT) {
								ofFlow.setDstPort("*");
								ofFlow.setSrcPort("*");
							}

							ofFlow.setSrcIp(retreivedNode.getValue().equals(dnsEndpoint) ? packet.getSrcIp() :
									retreivedNode.getValue().equals("*") ? "*": packet.getSrcIp());
							ofFlow.setEthType(packet.getEthType());
							ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
							ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
							ofFlow.setIdleTimeOut(idleTimeout);
							OFController.getInstance().addFlow(dpId, ofFlow);
							flowAdded = true;
						}
					}

				} else {
					OFFlow ofFlow = new OFFlow();
					ofFlow.setSrcMac(switchMac);
					ofFlow.setDstMac(deviceMac);
					ofFlow.setSrcIp(packet.getSrcIp());
					ofFlow.setSrcPort(packet.getSrcPort());
					ofFlow.setDstPort(packet.getDstPort());
					ofFlow.setEthType(packet.getEthType());
					ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
					ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
					ofFlow.setIdleTimeOut(idleTimeout);
					if (packet.getTcpFlag() == SimPacket.Flag.RST_ACK) {
						//attack rate limit.
						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_INTERNET
								, "*");
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == 6) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit >= EDGE_LIMIT) {
							ofFlow.setDstPort("*");
							ofFlow.setSrcPort("*");
						}
					}
					OFController.getInstance().addFlow(dpId, ofFlow);
				}
				return;
			}

			//udp
			if ((packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) &&
					packet.getIpProto().equals(Constants.UDP_PROTO)) {
				EdgeNode edgeNode = new EdgeNode();
				edgeNode.setSourcePort(Integer.parseInt(packet.getSrcPort()));
				edgeNode.setDestPort(Integer.parseInt(packet.getDstPort()));
				edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
				edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2), 16));

				boolean flowAdded =false;
				for (String dnsEndpoint : endpoints) {
					EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.FROM_INTERNET, dnsEndpoint, edgeNode);
					if (retreivedNode == null) {
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(switchMac);
						ofFlow.setDstMac(deviceMac);
						ofFlow.setSrcIp(packet.getSrcIp());
						ofFlow.setSrcPort(packet.getSrcPort());
						ofFlow.setDstPort(packet.getDstPort());

							//attack rate limit.
						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_INTERNET
								, dnsEndpoint);
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit >= EDGE_LIMIT) {
							ofFlow.setDstPort("*");
							ofFlow.setSrcPort("*");
						} else {
							deviceNode.addNode(DeviceNode.Directions.FROM_INTERNET, dnsEndpoint, edgeNode);
						}

						ofFlow.setEthType(packet.getEthType());
						ofFlow.setIpProto(packet.getIpProto());
						ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						if (!ofFlow.getSrcPort().equals(Constants.DNS_PORT) && !flowAdded) {
							OFController.getInstance().addFlow(dpId, ofFlow);
							flowAdded = true;
						}
					} else if (!flowAdded){
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(switchMac);
						ofFlow.setDstMac(deviceMac);
						ofFlow.setSrcIp(retreivedNode.getValue().equals(dnsEndpoint) ? packet.getSrcIp() :
								retreivedNode.getValue().equals("*") ? "*": packet.getSrcIp());
						ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
						boolean singleSourcePortValue = retreivedNode.getEdges().get(0).getSourcePortStart()
								== retreivedNode.getEdges().get(0).getSourcePortEnd();
						boolean singleDestPortValue = retreivedNode.getEdges().get(0).getDestPortStart()
								== retreivedNode.getEdges().get(0).getDestPortEnd();

						if (singleSourcePortValue) {
							ofFlow.setSrcPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getSourcePortEnd()));
						}

						if (singleDestPortValue) {
							ofFlow.setDstPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getDestPortEnd()));
						}

						if (!singleDestPortValue && !singleSourcePortValue) {
							ofFlow.setDstPort(packet.getDstPort());
							ofFlow.setSrcPort(packet.getSrcPort());

						}

						//attack rate limit.
						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_INTERNET
								, retreivedNode.getValue());
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit >= EDGE_LIMIT) {
							ofFlow.setDstPort("*");
							ofFlow.setSrcPort("*");
						}

						ofFlow.setEthType(packet.getEthType());
						ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						if (!ofFlow.getSrcPort().equals(Constants.DNS_PORT)) {
							OFController.getInstance().addFlow(dpId, ofFlow);
							flowAdded = true;
						}
					}
				}
				return;
			}
			//icmp
			if ((packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) &&
					packet.getIpProto().equals(Constants.ICMP_PROTO)) {
				EdgeNode edgeNode = new EdgeNode();
				edgeNode.setIcmpCode(Integer.parseInt(packet.getIcmpCode()));
				edgeNode.setIcmpType(Integer.parseInt(packet.getIcmpType()));
				edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
				edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2), 16));

				boolean flowAdded =false;
				for (String dnsEndpoint : endpoints) {
					EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.FROM_INTERNET, dnsEndpoint, edgeNode);
					if (retreivedNode == null) {
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(switchMac);
						ofFlow.setDstMac(deviceMac);
						ofFlow.setSrcIp(packet.getSrcIp());
						ofFlow.setIcmpCode(packet.getIcmpCode());
						ofFlow.setIcmpType(packet.getIcmpType());
						ofFlow.setEthType(packet.getEthType());
						ofFlow.setIpProto(packet.getIpProto());
						ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						if (!flowAdded) {
							OFController.getInstance().addFlow(dpId, ofFlow);
							flowAdded = true;
						}
						deviceNode.addNode(DeviceNode.Directions.FROM_INTERNET, dnsEndpoint, edgeNode);
					} else if (!flowAdded) {
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(switchMac);
						ofFlow.setDstMac(deviceMac);
						ofFlow.setSrcIp(retreivedNode.getValue().equals(dnsEndpoint) ? packet.getSrcIp() :
								retreivedNode.getValue().equals("*") ? "*" : packet.getSrcIp());
						ofFlow.setIcmpType(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIcmpType()));
						ofFlow.setIcmpCode(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIcmpCode()));
						ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
						ofFlow.setEthType(packet.getEthType());
						ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						OFController.getInstance().addFlow(dpId, ofFlow);
						flowAdded = true;
					}
				}
				return;
			}

		}
		//ToInternet //todo
		//workaround to mac fix -- have to test.
		boolean publicIp = true;
		if (packet.getDstIp() != null) {
			for (String ipx : ipList) {
				if (packet.getDstIp().startsWith(ipx) || isMulticastorBroadcast(packet.getDstMac()) ||
						packet.getDstIp().startsWith(gatewayIpv6.split(":")[0])) {
					publicIp = false;
					break;
				}
			}
		}
//		if (packet.getSrcMac().equals(deviceMac) && packet.getDstMac().equals(switchMac)
//				 && packet.getDstIp() != null && !packet.getDstIp().equals(gatewayIp)) {
		if (packet.getSrcMac().equals(deviceMac)
				&& packet.getDstIp() != null && publicIp) {
			endpoint = packet.getDstIp();
			List<String> endpoints = getDns(endpoint);

			//tcp
			if ((packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) &&
					packet.getIpProto().equals(Constants.TCP_PROTO)) {
				if (packet.getTcpFlag() == SimPacket.Flag.SYN) {
					EdgeNode edgeNode = new EdgeNode();
					edgeNode.setDestPort(Integer.parseInt(packet.getDstPort()));
					edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
					edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2),16));

					boolean flowAdded =false;
					for (String dnsEndpoint : endpoints) {
						EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.TO_INTERNET, dnsEndpoint, edgeNode);
						if (retreivedNode == null) {

							int edgeLimit = 0;
							EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_INTERNET
									, dnsEndpoint);
							if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
								for (EdgeNode ex : edd.getEdges()) {
									if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
										edgeLimit++;
									}
								}
							}
							if (edgeLimit < EDGE_LIMIT) {
								deviceNode.addNode(DeviceNode.Directions.TO_INTERNET, dnsEndpoint, edgeNode);
							}

							OFFlow ofFlow = new OFFlow();
							ofFlow.setSrcMac(deviceMac);
							ofFlow.setDstMac(packet.getDstMac());
							ofFlow.setDstIp(packet.getDstIp());
							if (edgeLimit < EDGE_LIMIT) {
								ofFlow.setDstPort(packet.getDstPort());
							}
							ofFlow.setEthType(packet.getEthType());
							ofFlow.setIpProto(packet.getIpProto());
							ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
							ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
							ofFlow.setIdleTimeOut(idleTimeout);
							if (!flowAdded) {
								OFController.getInstance().addFlow(dpId, ofFlow);
								flowAdded = true;
							}
						} else if (!flowAdded) {
							OFFlow ofFlow = new OFFlow();
							ofFlow.setSrcMac(deviceMac);
							ofFlow.setDstMac(packet.getDstMac());
							ofFlow.setDstIp(retreivedNode.getValue().equals(dnsEndpoint) ? packet.getDstIp() :
									retreivedNode.getValue().equals("*") ? "*" : packet.getDstIp());
							ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
							boolean singleSourcePortValue = retreivedNode.getEdges().get(0).getSourcePortStart()
									== retreivedNode.getEdges().get(0).getSourcePortEnd();
							boolean singleDestPortValue = retreivedNode.getEdges().get(0).getDestPortStart()
									== retreivedNode.getEdges().get(0).getDestPortEnd();

							if (singleSourcePortValue) {
								ofFlow.setSrcPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getSourcePortEnd()));
							}

							if (singleDestPortValue) {
								ofFlow.setDstPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getDestPortEnd()));
							}

							if (!singleDestPortValue && !singleSourcePortValue) {
								ofFlow.setDstPort(packet.getDstPort());
								ofFlow.setSrcPort(packet.getSrcPort());
							}

							//attack rate limit.
							int edgeLimit = 0;
							EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_INTERNET
									, retreivedNode.getValue());
							if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
								for (EdgeNode ex : edd.getEdges()) {
									if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
										edgeLimit++;
									}
								}
							}
							if (edgeLimit >= EDGE_LIMIT) {
								ofFlow.setDstPort("*");
								ofFlow.setSrcPort("*");
							}

							ofFlow.setEthType(packet.getEthType());
							ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
							ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
							ofFlow.setIdleTimeOut(idleTimeout);
							OFController.getInstance().addFlow(dpId, ofFlow);
							flowAdded = true;
						}
					}

				} else if (packet.getTcpFlag() == SimPacket.Flag.SYN_ACK) {

					EdgeNode edgeNode = new EdgeNode();
					edgeNode.setSourcePort(Integer.parseInt(packet.getSrcPort()));
					edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
					edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2),16));

					boolean flowAdded =false;
					for (String dnsEndpoint : endpoints) {
						EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.TO_INTERNET, dnsEndpoint, edgeNode);
						if (retreivedNode == null) {

							int edgeLimit = 0;
							EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_INTERNET
									, dnsEndpoint);
							if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
								for (EdgeNode ex : edd.getEdges()) {
									if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
										edgeLimit++;
									}
								}
							}
							if (edgeLimit < EDGE_LIMIT) {
								deviceNode.addNode(DeviceNode.Directions.TO_INTERNET, dnsEndpoint, edgeNode);
							}

							OFFlow ofFlow = new OFFlow();
							ofFlow.setSrcMac(deviceMac);
							ofFlow.setDstMac(packet.getDstMac());
							ofFlow.setSrcIp(packet.getDstIp());
							if (edgeLimit < EDGE_LIMIT) {
								ofFlow.setSrcPort(packet.getSrcPort());
							}
							ofFlow.setEthType(packet.getEthType());
							ofFlow.setIpProto(packet.getIpProto());
							ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
							ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
							ofFlow.setIdleTimeOut(idleTimeout);
							if(!flowAdded) {OFController.getInstance().addFlow(dpId, ofFlow);
								flowAdded = true;
							}

						} else if(!flowAdded){
							OFFlow ofFlow = new OFFlow();
							ofFlow.setSrcMac(deviceMac);
							ofFlow.setDstMac(packet.getDstMac());
							ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
							boolean singleSourcePortValue = retreivedNode.getEdges().get(0).getSourcePortStart()
									== retreivedNode.getEdges().get(0).getSourcePortEnd();
							boolean singleDestPortValue = retreivedNode.getEdges().get(0).getDestPortStart()
									== retreivedNode.getEdges().get(0).getDestPortEnd();

							if (singleSourcePortValue) {
								ofFlow.setSrcPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getSourcePortEnd()));
							}

							if (singleDestPortValue) {
								ofFlow.setDstPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getDestPortEnd()));
							}

							if (!singleDestPortValue && !singleSourcePortValue) {
								ofFlow.setDstPort(packet.getDstPort());
								ofFlow.setSrcPort(packet.getSrcPort());
							}

							//attack rate limit.
							int edgeLimit = 0;
							EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_INTERNET
									, retreivedNode.getValue());
							if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
								for (EdgeNode ex : edd.getEdges()) {
									if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
										edgeLimit++;
									}
								}
							}
							if (edgeLimit >= EDGE_LIMIT) {
								ofFlow.setDstPort("*");
								ofFlow.setSrcPort("*");
							}


							ofFlow.setDstIp(retreivedNode.getValue().equals(dnsEndpoint) ? packet.getDstIp() :
									retreivedNode.getValue().equals("*") ? "*" : packet.getDstIp());
							ofFlow.setEthType(packet.getEthType());
							ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
							ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
							ofFlow.setIdleTimeOut(idleTimeout);
							OFController.getInstance().addFlow(dpId, ofFlow);
							flowAdded = true;
						}
					}

				} else {
					OFFlow ofFlow = new OFFlow();
					ofFlow.setSrcMac(deviceMac);
					ofFlow.setDstMac(packet.getDstMac());
					ofFlow.setDstIp(packet.getDstIp());
					ofFlow.setSrcPort(packet.getSrcPort());
					ofFlow.setDstPort(packet.getDstPort());
					ofFlow.setEthType(packet.getEthType());
					ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
					ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
					ofFlow.setIdleTimeOut(idleTimeout);
					if (packet.getTcpFlag() == SimPacket.Flag.RST_ACK) {
						//attack rate limit.
						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_INTERNET
								, "*");
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == 6) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit >= EDGE_LIMIT) {
							ofFlow.setDstPort("*");
							ofFlow.setSrcPort("*");
						}
					}
					OFController.getInstance().addFlow(dpId, ofFlow);
				}
				return;
			}

			//udp
			if ((packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) &&
					packet.getIpProto().equals(Constants.UDP_PROTO)) {
				EdgeNode edgeNode = new EdgeNode();
				edgeNode.setSourcePort(Integer.parseInt(packet.getSrcPort()));
				edgeNode.setDestPort(Integer.parseInt(packet.getDstPort()));
				edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
				edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2), 16));

				boolean flowAdded =false;
				for (String dnsEndpoint : endpoints) {
					EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.TO_INTERNET, dnsEndpoint, edgeNode);
					if (retreivedNode == null) {
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						ofFlow.setDstMac(packet.getDstMac());
						ofFlow.setDstIp(packet.getDstIp());
						ofFlow.setSrcPort(packet.getSrcPort());
						ofFlow.setDstPort(packet.getDstPort());
						//attack rate limit.
						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_INTERNET
								, dnsEndpoint);
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit >= EDGE_LIMIT) {
							ofFlow.setDstPort("*");
							ofFlow.setSrcPort("*");
						} else {
							deviceNode.addNode(DeviceNode.Directions.TO_INTERNET, dnsEndpoint, edgeNode);
						}
						ofFlow.setEthType(packet.getEthType());
						ofFlow.setIpProto(packet.getIpProto());
						ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						if (!flowAdded) {
							OFController.getInstance().addFlow(dpId, ofFlow);
							flowAdded = true;
						}

					} else if (!flowAdded){
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						ofFlow.setDstMac(packet.getDstMac());
						ofFlow.setDstIp(retreivedNode.getValue().equals(dnsEndpoint) ? packet.getDstIp() :
								retreivedNode.getValue().equals("*") ? "*" : packet.getDstIp());

						ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
						boolean singleSourcePortValue = retreivedNode.getEdges().get(0).getSourcePortStart()
								== retreivedNode.getEdges().get(0).getSourcePortEnd();
						boolean singleDestPortValue = retreivedNode.getEdges().get(0).getDestPortStart()
								== retreivedNode.getEdges().get(0).getDestPortEnd();

						if (singleSourcePortValue) {
							ofFlow.setSrcPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getSourcePortEnd()));
						}

						if (singleDestPortValue) {
							ofFlow.setDstPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getDestPortEnd()));
						}

						if (!singleDestPortValue && !singleSourcePortValue) {
							ofFlow.setDstPort(packet.getDstPort());
							ofFlow.setSrcPort(packet.getSrcPort());
						}

						//attack rate limit.
						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_INTERNET
								, retreivedNode.getValue());
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit >= EDGE_LIMIT) {
							ofFlow.setDstPort("*");
							ofFlow.setSrcPort("*");
						}

						ofFlow.setEthType(packet.getEthType());
						ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						OFController.getInstance().addFlow(dpId, ofFlow);
						flowAdded = true;
					}
				}
				return;
			}

			//icmp
			if ((packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) &&
					packet.getIpProto().equals(Constants.ICMP_PROTO)) {
				EdgeNode edgeNode = new EdgeNode();
				edgeNode.setIcmpCode(Integer.parseInt(packet.getIcmpCode()));
				edgeNode.setIcmpType(Integer.parseInt(packet.getIcmpType()));
				edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
				edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2), 16));
				boolean flowAdded =false;
				for (String dnsEndpoint : endpoints) {
					EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.TO_INTERNET, dnsEndpoint, edgeNode);
					if (retreivedNode == null) {
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						ofFlow.setDstMac(packet.getDstMac());
						ofFlow.setDstIp(packet.getDstIp());
						ofFlow.setIcmpCode(packet.getIcmpCode());
						ofFlow.setIcmpType(packet.getIcmpType());
						ofFlow.setEthType(packet.getEthType());
						ofFlow.setIpProto(packet.getIpProto());
						ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						if (!flowAdded) {
							OFController.getInstance().addFlow(dpId, ofFlow);
							flowAdded = true;
						}
						deviceNode.addNode(DeviceNode.Directions.TO_INTERNET, dnsEndpoint, edgeNode);
					} else if (!flowAdded){
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						ofFlow.setDstMac(packet.getDstMac());
						ofFlow.setDstIp(retreivedNode.getValue().equals(dnsEndpoint) ? packet.getDstIp() :
								retreivedNode.getValue().equals("*") ? "*" : packet.getDstIp());
						ofFlow.setIcmpType(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIcmpType()));
						ofFlow.setIcmpCode(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIcmpCode()));
						ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
						ofFlow.setEthType(packet.getEthType());
						ofFlow.setPriority(REACTIVE_INTERNET_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						OFController.getInstance().addFlow(dpId, ofFlow);
						flowAdded = true;
					}
				}
				return;
			}

		}

		//FromLocal //todo

		if (packet.getDstMac().equals(deviceMac)) {
			if (!(packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4))) {
				endpoint = WILDCARD;
			} else {
				endpoint = packet.getSrcIp();
				endpoint = getControllerMapping(endpoint, packet.getSrcPort(), packet.getSrcMac());
			}
			//tcp
			if ((packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) &&
					packet.getIpProto().equals(Constants.TCP_PROTO)) {
				if (packet.getTcpFlag() == SimPacket.Flag.SYN) {
					EdgeNode edgeNode = new EdgeNode();
					edgeNode.setDestPort(Integer.parseInt(packet.getDstPort()));
					edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
					edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2),16));

					EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.FROM_LOCAL,endpoint, edgeNode);
					if (retreivedNode == null) {

						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_LOCAL
								, endpoint);
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit < EDGE_LIMIT) {
							deviceNode.addNode(DeviceNode.Directions.FROM_LOCAL, endpoint, edgeNode);
						}


						OFFlow ofFlow = new OFFlow();
						if(isMulticastorBroadcast(packet.getSrcMac())) ofFlow.setSrcMac(packet.getSrcMac());
						ofFlow.setDstMac(deviceMac);
						if (!endpoint.equals("*")) {
							ofFlow.setSrcIp(packet.getSrcIp());
						}
						if (edgeLimit < EDGE_LIMIT) {
							ofFlow.setDstPort(packet.getDstPort());
						}
						ofFlow.setEthType(packet.getEthType());
						ofFlow.setIpProto(packet.getIpProto());
						ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						OFController.getInstance().addFlow(dpId, ofFlow);

					} else {
						OFFlow ofFlow = new OFFlow();
						if(isMulticastorBroadcast(packet.getSrcMac())) ofFlow.setSrcMac(packet.getSrcMac());
						ofFlow.setDstMac(deviceMac);
						ofFlow.setSrcIp(retreivedNode.getValue().equals("*") ? "*" : packet.getSrcIp());
						ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
						boolean singleSourcePortValue = retreivedNode.getEdges().get(0).getSourcePortStart()
								== retreivedNode.getEdges().get(0).getSourcePortEnd();
						boolean singleDestPortValue = retreivedNode.getEdges().get(0).getDestPortStart()
								== retreivedNode.getEdges().get(0).getDestPortEnd();

						if (singleSourcePortValue) {
							ofFlow.setSrcPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getSourcePortEnd()));
						}

						if (singleDestPortValue) {
							ofFlow.setDstPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getDestPortEnd()));
						}

						if (!singleDestPortValue && !singleSourcePortValue) {
							ofFlow.setDstPort(packet.getDstPort());
							ofFlow.setSrcPort(packet.getSrcPort());
						}

						//attack rate limit.
						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_LOCAL
								, retreivedNode.getValue());
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit >= EDGE_LIMIT) {
							ofFlow.setDstPort("*");
							ofFlow.setSrcPort("*");
						}

						ofFlow.setEthType(packet.getEthType());
						ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						OFController.getInstance().addFlow(dpId, ofFlow);
					}

				} else if (packet.getTcpFlag() == SimPacket.Flag.SYN_ACK) {

					EdgeNode edgeNode = new EdgeNode();
					edgeNode.setSourcePort(Integer.parseInt(packet.getSrcPort()));
					edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
					edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2),16));

					EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.FROM_LOCAL,endpoint, edgeNode);
					if (retreivedNode == null) {

						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_LOCAL
								, endpoint);
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit < EDGE_LIMIT) {
							deviceNode.addNode(DeviceNode.Directions.FROM_LOCAL, endpoint, edgeNode);
						}


						OFFlow ofFlow = new OFFlow();
						if(isMulticastorBroadcast(packet.getSrcMac())) ofFlow.setSrcMac(packet.getSrcMac());
						ofFlow.setDstMac(deviceMac);
						if (!endpoint.equals("*")) {
							ofFlow.setSrcIp(packet.getSrcIp());
						}
						if (edgeLimit < EDGE_LIMIT) {
							ofFlow.setSrcPort(packet.getSrcPort());
						}
						ofFlow.setEthType(packet.getEthType());
						ofFlow.setIpProto(packet.getIpProto());
						ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						OFController.getInstance().addFlow(dpId, ofFlow);
					} else {
						OFFlow ofFlow = new OFFlow();
						if(isMulticastorBroadcast(packet.getSrcMac())) ofFlow.setSrcMac(packet.getSrcMac());
						ofFlow.setDstMac(deviceMac);
						ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
						boolean singleSourcePortValue = retreivedNode.getEdges().get(0).getSourcePortStart()
								== retreivedNode.getEdges().get(0).getSourcePortEnd();
						boolean singleDestPortValue = retreivedNode.getEdges().get(0).getDestPortStart()
								== retreivedNode.getEdges().get(0).getDestPortEnd();

						if (singleSourcePortValue) {
							ofFlow.setSrcPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getSourcePortEnd()));
						}

						if (singleDestPortValue) {
							ofFlow.setDstPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getDestPortEnd()));
						}

						if (!singleDestPortValue && !singleSourcePortValue) {
							ofFlow.setDstPort(packet.getDstPort());
							ofFlow.setSrcPort(packet.getSrcPort());
						}

						//attack rate limit.
						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_LOCAL
								, retreivedNode.getValue());
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit >= EDGE_LIMIT) {
							ofFlow.setDstPort("*");
							ofFlow.setSrcPort("*");
						}

						ofFlow.setSrcIp(retreivedNode.getValue().equals("*") ? "*" : packet.getSrcIp());
						ofFlow.setEthType(packet.getEthType());
						ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						OFController.getInstance().addFlow(dpId, ofFlow);
					}

				} else {


					OFFlow ofFlow = new OFFlow();
					if(isMulticastorBroadcast(packet.getSrcMac())) ofFlow.setSrcMac(packet.getSrcMac());
					ofFlow.setDstMac(deviceMac);
					ofFlow.setSrcIp(packet.getSrcIp());
					ofFlow.setSrcPort(packet.getSrcPort());
					ofFlow.setDstPort(packet.getDstPort());

					int edgeLimit = 0;
					if (packet.getTcpFlag() == SimPacket.Flag.RST_ACK) {
						//attack rate limit.
						edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_LOCAL
								, "*");
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == 6) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit >= EDGE_LIMIT) {
							ofFlow.setSrcIp("*");
							ofFlow.setDstPort("*");
							ofFlow.setSrcPort("*");
						}
					}

					ofFlow.setEthType(packet.getEthType());
					ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
					ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
					ofFlow.setIdleTimeOut(idleTimeout);
					OFController.getInstance().addFlow(dpId, ofFlow);
				}
				return;
			}

			//udp
			if ((packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) &&
					packet.getIpProto().equals(Constants.UDP_PROTO)) {


				EdgeNode edgeNode = new EdgeNode();
				edgeNode.setSourcePort(Integer.parseInt(packet.getSrcPort()));
				edgeNode.setDestPort(Integer.parseInt(packet.getDstPort()));
				edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
				edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2), 16));

				EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.FROM_LOCAL, endpoint, edgeNode);
				if (retreivedNode == null) {
					OFFlow ofFlow = new OFFlow();
					if(isMulticastorBroadcast(packet.getSrcMac())) ofFlow.setSrcMac(packet.getSrcMac());
					ofFlow.setDstMac(deviceMac);
					if (!endpoint.equals("*")) {
						ofFlow.setSrcIp(packet.getSrcIp());
					}
					ofFlow.setSrcPort(packet.getSrcPort());
					ofFlow.setDstPort(packet.getDstPort());

					//attack rate limit.
					int edgeLimit = 0;
					EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_LOCAL
							, endpoint);
					if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
						for (EdgeNode ex : edd.getEdges()) {
							if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
								edgeLimit++;
							}
						}
					}
					if (edgeLimit >= EDGE_LIMIT) {
						ofFlow.setDstPort("*");
						ofFlow.setSrcPort("*");
					} else {
						deviceNode.addNode(DeviceNode.Directions.FROM_LOCAL, endpoint, edgeNode);
					}


					ofFlow.setEthType(packet.getEthType());
					ofFlow.setIpProto(packet.getIpProto());
					ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
					ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
					ofFlow.setIdleTimeOut(idleTimeout);
					if (!ofFlow.getSrcPort().equals(Constants.DNS_PORT)) {
						OFController.getInstance().addFlow(dpId, ofFlow);
					}

				} else {
					OFFlow ofFlow = new OFFlow();
					if(isMulticastorBroadcast(packet.getSrcMac())) ofFlow.setSrcMac(packet.getSrcMac());
					ofFlow.setDstMac(deviceMac);
					ofFlow.setSrcIp(retreivedNode.getValue().equals("*") ? "*" : packet.getSrcIp());

					ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
					boolean singleSourcePortValue = retreivedNode.getEdges().get(0).getSourcePortStart()
							== retreivedNode.getEdges().get(0).getSourcePortEnd();
					boolean singleDestPortValue = retreivedNode.getEdges().get(0).getDestPortStart()
							== retreivedNode.getEdges().get(0).getDestPortEnd();

					if (singleSourcePortValue) {
						ofFlow.setSrcPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getSourcePortEnd()));
					}

					if (singleDestPortValue) {
						ofFlow.setDstPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getDestPortEnd()));
					}

					if (!singleDestPortValue && !singleSourcePortValue) {
						ofFlow.setDstPort(packet.getDstPort());
						ofFlow.setSrcPort(packet.getSrcPort());

					}
					//attack rate limit.
					int edgeLimit = 0;
					EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_LOCAL
							, retreivedNode.getValue());
					if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
						for (EdgeNode ex : edd.getEdges()) {
							if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
								edgeLimit++;
							}
						}
					}
					if (edgeLimit >= EDGE_LIMIT) {
						ofFlow.setDstPort("*");
						ofFlow.setSrcPort("*");
					}

					ofFlow.setEthType(packet.getEthType());
					ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
					ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
					ofFlow.setIdleTimeOut(idleTimeout);
					if (!ofFlow.getSrcPort().equals(Constants.DNS_PORT)) {
						OFController.getInstance().addFlow(dpId, ofFlow);
					}
				}
				return;
			}

			//icmp
			if ((packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) &&
					packet.getIpProto().equals(Constants.ICMP_PROTO)) {
				EdgeNode edgeNode = new EdgeNode();
				edgeNode.setIcmpCode(Integer.parseInt(packet.getIcmpCode()));
				edgeNode.setIcmpType(Integer.parseInt(packet.getIcmpType()));
				edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
				edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2), 16));

				EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.FROM_LOCAL, endpoint, edgeNode);
				if (retreivedNode == null) {
					OFFlow ofFlow = new OFFlow();
					if(isMulticastorBroadcast(packet.getSrcMac())) ofFlow.setSrcMac(packet.getSrcMac());
					ofFlow.setDstMac(deviceMac);
					ofFlow.setSrcIp(packet.getSrcIp());
					ofFlow.setIcmpCode(packet.getIcmpCode());
					ofFlow.setIcmpType(packet.getIcmpType());
					ofFlow.setEthType(packet.getEthType());
					ofFlow.setIpProto(packet.getIpProto());
					ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
					ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
					ofFlow.setIdleTimeOut(idleTimeout);
					OFController.getInstance().addFlow(dpId, ofFlow);
					deviceNode.addNode(DeviceNode.Directions.FROM_LOCAL, endpoint, edgeNode);
				} else {
					OFFlow ofFlow = new OFFlow();
					if(isMulticastorBroadcast(packet.getSrcMac())) ofFlow.setSrcMac(packet.getSrcMac());
					ofFlow.setDstMac(deviceMac);
					ofFlow.setSrcIp(retreivedNode.getValue().equals("*") ? "*" : packet.getSrcIp());
					ofFlow.setIcmpType(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIcmpType()));
					ofFlow.setIcmpCode(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIcmpCode()));
					ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
					ofFlow.setEthType(packet.getEthType());
					ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
					ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
					ofFlow.setIdleTimeOut(idleTimeout);
					OFController.getInstance().addFlow(dpId, ofFlow);
				}
				return;
			}
		}
		//ToLocal

		if (packet.getSrcMac().equals(deviceMac)) {
			if (!(packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) ) {
				endpoint = WILDCARD;
			} else {
				endpoint = packet.getDstIp();
				endpoint = getControllerMapping(endpoint, packet.getDstPort(), packet.getDstMac());
			}
			//tcp
			if ((packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) &&
					packet.getIpProto().equals(Constants.TCP_PROTO)) {
				if (packet.getTcpFlag() == SimPacket.Flag.SYN) {
					EdgeNode edgeNode = new EdgeNode();
					edgeNode.setDestPort(Integer.parseInt(packet.getDstPort()));
					edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
					edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2),16));

					EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.TO_LOCAL,endpoint, edgeNode);
					if (retreivedNode == null) {

						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_LOCAL
								, endpoint);
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit < EDGE_LIMIT) {
							deviceNode.addNode(DeviceNode.Directions.TO_LOCAL, endpoint, edgeNode);
						}

						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						if(isMulticastorBroadcast(packet.getDstMac())) ofFlow.setDstMac(packet.getDstMac());
						if (!endpoint.equals("*")) {
							ofFlow.setDstIp(packet.getDstIp());
						}
						if (edgeLimit < EDGE_LIMIT) {
							ofFlow.setDstPort(packet.getDstPort());
						}
						ofFlow.setEthType(packet.getEthType());
						ofFlow.setIpProto(packet.getIpProto());
						ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						OFController.getInstance().addFlow(dpId, ofFlow);
					} else {
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						if(isMulticastorBroadcast(packet.getDstMac())) ofFlow.setDstMac(packet.getDstMac());
						ofFlow.setDstIp(retreivedNode.getValue().equals("*") ? "*" : packet.getDstIp());
						ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
						boolean singleSourcePortValue = retreivedNode.getEdges().get(0).getSourcePortStart()
								== retreivedNode.getEdges().get(0).getSourcePortEnd();
						boolean singleDestPortValue = retreivedNode.getEdges().get(0).getDestPortStart()
								== retreivedNode.getEdges().get(0).getDestPortEnd();

						if (singleSourcePortValue) {
							ofFlow.setSrcPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getSourcePortEnd()));
						}

						if (singleDestPortValue) {
							ofFlow.setDstPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getDestPortEnd()));
						}

						if (!singleDestPortValue && !singleSourcePortValue) {
							ofFlow.setDstPort(packet.getDstPort());
							ofFlow.setSrcPort(packet.getSrcPort());

						}

						//attack rate limit.
						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_LOCAL
								, retreivedNode.getValue());
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit >= EDGE_LIMIT) {
							ofFlow.setDstPort("*");
							ofFlow.setSrcPort("*");
						}

						ofFlow.setEthType(packet.getEthType());
						ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						OFController.getInstance().addFlow(dpId, ofFlow);
					}

				} else if (packet.getTcpFlag() == SimPacket.Flag.SYN_ACK) {

					EdgeNode edgeNode = new EdgeNode();
					edgeNode.setSourcePort(Integer.parseInt(packet.getSrcPort()));
					edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
					edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2),16));

					EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.TO_LOCAL,endpoint, edgeNode);
					if (retreivedNode == null) {
						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_LOCAL
								, endpoint);
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit < EDGE_LIMIT) {
							deviceNode.addNode(DeviceNode.Directions.TO_LOCAL, endpoint, edgeNode);
						}

						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						if(isMulticastorBroadcast(packet.getDstMac())) ofFlow.setDstMac(packet.getDstMac());
						if (!endpoint.equals("*")) {
							ofFlow.setSrcIp(packet.getDstIp());
						}
						if (edgeLimit < EDGE_LIMIT) {
							ofFlow.setSrcPort(packet.getSrcPort());
						}
						ofFlow.setEthType(packet.getEthType());
						ofFlow.setIpProto(packet.getIpProto());
						ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						OFController.getInstance().addFlow(dpId, ofFlow);
					} else {
						OFFlow ofFlow = new OFFlow();
						ofFlow.setSrcMac(deviceMac);
						if(isMulticastorBroadcast(packet.getDstMac())) ofFlow.setDstMac(packet.getDstMac());
						ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
						boolean singleSourcePortValue = retreivedNode.getEdges().get(0).getSourcePortStart()
								== retreivedNode.getEdges().get(0).getSourcePortEnd();
						boolean singleDestPortValue = retreivedNode.getEdges().get(0).getDestPortStart()
								== retreivedNode.getEdges().get(0).getDestPortEnd();

						if (singleSourcePortValue) {
							ofFlow.setSrcPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getSourcePortEnd()));
						}

						if (singleDestPortValue) {
							ofFlow.setDstPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getDestPortEnd()));
						}

						if (!singleDestPortValue && !singleSourcePortValue) {
							ofFlow.setDstPort(packet.getDstPort());
							ofFlow.setSrcPort(packet.getSrcPort());

						}
						//attack rate limit.
						int edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_LOCAL
								, retreivedNode.getValue());
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit >= EDGE_LIMIT) {
							ofFlow.setDstPort("*");
							ofFlow.setSrcPort("*");
						}

						ofFlow.setDstIp(retreivedNode.getValue().equals("*") ? "*" : packet.getDstIp());
						ofFlow.setEthType(packet.getEthType());
						ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
						ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
						ofFlow.setIdleTimeOut(idleTimeout);
						OFController.getInstance().addFlow(dpId, ofFlow);
					}

				} else {
					OFFlow ofFlow = new OFFlow();
					ofFlow.setSrcMac(deviceMac);
					if(isMulticastorBroadcast(packet.getDstMac())) ofFlow.setDstMac(packet.getDstMac());
					ofFlow.setDstIp(packet.getDstIp());
					ofFlow.setSrcPort(packet.getSrcPort());
					ofFlow.setDstPort(packet.getDstPort());

					int edgeLimit = 0;

					if (packet.getTcpFlag() == SimPacket.Flag.RST_ACK) {
						//attack rate limit.
						edgeLimit = 0;
						EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.FROM_LOCAL
								, "*");
						if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
							for (EdgeNode ex : edd.getEdges()) {
								if (ex.getIpProtocol() == 6) {
									edgeLimit++;
								}
							}
						}
						if (edgeLimit >= EDGE_LIMIT) {
							ofFlow.setDstIp("*");
							ofFlow.setDstPort("*");
							ofFlow.setSrcPort("*");
						}
					}


					ofFlow.setEthType(packet.getEthType());
					ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
					ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
					ofFlow.setIdleTimeOut(idleTimeout);
					OFController.getInstance().addFlow(dpId, ofFlow);
				}
				return;
			}

			//udp
			if ((packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) &&
					packet.getIpProto().equals(Constants.UDP_PROTO)) {
				EdgeNode edgeNode = new EdgeNode();
				edgeNode.setSourcePort(Integer.parseInt(packet.getSrcPort()));
				edgeNode.setDestPort(Integer.parseInt(packet.getDstPort()));
				edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
				edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2), 16));

				EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.TO_LOCAL, endpoint, edgeNode);
				if (retreivedNode == null) {
					OFFlow ofFlow = new OFFlow();
					ofFlow.setSrcMac(deviceMac);
					if(isMulticastorBroadcast(packet.getDstMac())) ofFlow.setDstMac(packet.getDstMac());
					if (!endpoint.equals("*")) {
						ofFlow.setDstIp(packet.getDstIp());
					}
					ofFlow.setSrcPort(packet.getSrcPort());
					ofFlow.setDstPort(packet.getDstPort());

					//attack rate limit.
					int edgeLimit = 0;
					EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_LOCAL
							, endpoint);
					if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
						for (EdgeNode ex : edd.getEdges()) {
							if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
								edgeLimit++;
							}
						}
					}
					if (edgeLimit >= EDGE_LIMIT) {
						ofFlow.setDstPort("*");
						ofFlow.setSrcPort("*");
					} else {
						deviceNode.addNode(DeviceNode.Directions.TO_LOCAL, endpoint, edgeNode);
					}

					ofFlow.setEthType(packet.getEthType());
					ofFlow.setIpProto(packet.getIpProto());
					ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
					ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
					ofFlow.setIdleTimeOut(idleTimeout);
					OFController.getInstance().addFlow(dpId, ofFlow);

				} else {
					OFFlow ofFlow = new OFFlow();
					ofFlow.setSrcMac(deviceMac);
					if(isMulticastorBroadcast(packet.getDstMac())) ofFlow.setDstMac(packet.getDstMac());
					ofFlow.setDstIp(retreivedNode.getValue().equals("*") ? "*" : packet.getDstIp());

					ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
					boolean singleSourcePortValue = retreivedNode.getEdges().get(0).getSourcePortStart()
							== retreivedNode.getEdges().get(0).getSourcePortEnd();
					boolean singleDestPortValue = retreivedNode.getEdges().get(0).getDestPortStart()
							== retreivedNode.getEdges().get(0).getDestPortEnd();

					if (singleSourcePortValue) {
						ofFlow.setSrcPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getSourcePortEnd()));
					}

					if (singleDestPortValue) {
						ofFlow.setDstPort(getEdgeNodeValue(retreivedNode.getEdges().get(0).getDestPortEnd()));
					}

					if (!singleDestPortValue && !singleSourcePortValue) {
						ofFlow.setDstPort(packet.getDstPort());
						ofFlow.setSrcPort(packet.getSrcPort());

					}

					//attack rate limit.
					int edgeLimit = 0;
					EndpointNode edd = deviceNode.getEndpointNode(DeviceNode.Directions.TO_LOCAL
							, retreivedNode.getValue());
					if (edd != null && edd.getEdges().size() >= EDGE_LIMIT) {
						for (EdgeNode ex : edd.getEdges()) {
							if (ex.getIpProtocol() == edgeNode.getIpProtocol()) {
								edgeLimit++;
							}
						}
					}
					if (edgeLimit >= EDGE_LIMIT) {
						ofFlow.setDstPort("*");
						ofFlow.setSrcPort("*");
					}

					ofFlow.setEthType(packet.getEthType());
					ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
					ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
					ofFlow.setIdleTimeOut(idleTimeout);
					OFController.getInstance().addFlow(dpId, ofFlow);
				}
				return;
			}

			//icmp
			if ((packet.getEthType().equals(Constants.ETH_TYPE_IPV6) || packet.getEthType().equals(Constants.ETH_TYPE_IPV4)) &&
					packet.getIpProto().equals(Constants.ICMP_PROTO)) {
				EdgeNode edgeNode = new EdgeNode();
				edgeNode.setIcmpCode(Integer.parseInt(packet.getIcmpCode()));
				edgeNode.setIcmpType(Integer.parseInt(packet.getIcmpType()));
				edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
				edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2), 16));

				EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.TO_LOCAL, endpoint, edgeNode);
				if (retreivedNode == null) {
					OFFlow ofFlow = new OFFlow();
					ofFlow.setSrcMac(deviceMac);
					if(isMulticastorBroadcast(packet.getDstMac())) ofFlow.setDstMac(packet.getDstMac());
					ofFlow.setDstIp(packet.getDstIp());
					ofFlow.setIcmpCode(packet.getIcmpCode());
					ofFlow.setIcmpType(packet.getIcmpType());
					ofFlow.setEthType(packet.getEthType());
					ofFlow.setIpProto(packet.getIpProto());
					ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
					ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
					ofFlow.setIdleTimeOut(idleTimeout);
					OFController.getInstance().addFlow(dpId, ofFlow);
					deviceNode.addNode(DeviceNode.Directions.TO_LOCAL, endpoint, edgeNode);
				} else {
					OFFlow ofFlow = new OFFlow();
					ofFlow.setSrcMac(deviceMac);
					if(isMulticastorBroadcast(packet.getDstMac())) ofFlow.setDstMac(packet.getDstMac());
					ofFlow.setDstIp(retreivedNode.getValue().equals("*") ? "*" : packet.getDstIp());
					ofFlow.setIcmpType(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIcmpType()));
					ofFlow.setIcmpCode(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIcmpCode()));
					ofFlow.setIpProto(getEdgeNodeValue(retreivedNode.getEdges().get(0).getIpProtocol()));
					ofFlow.setEthType(packet.getEthType());
					ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
					ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
					ofFlow.setIdleTimeOut(idleTimeout);
					OFController.getInstance().addFlow(dpId, ofFlow);
				}
				return;
			}
//0006
			EdgeNode edgeNode = new EdgeNode();
			edgeNode.setEthType(Integer.parseInt(packet.getEthType().substring(2), 16));
			if (packet.getIpProto() != null && !packet.getIpProto().equals("*")) {
				edgeNode.setIpProtocol(Integer.parseInt(packet.getIpProto()));
			}
			EndpointNode retreivedNode = deviceNode.getNode(DeviceNode.Directions.TO_LOCAL, endpoint, edgeNode);
			if (retreivedNode == null) {
				OFFlow ofFlow = new OFFlow();
				ofFlow.setSrcMac(deviceMac);
				if(isMulticastorBroadcast(packet.getDstMac())) ofFlow.setDstMac(packet.getDstMac());
				ofFlow.setEthType(packet.getEthType());
				if (packet.getIpProto() != null && !packet.getIpProto().equals("*")) {
					ofFlow.setIpProto(packet.getIpProto());
				}
				ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
				ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
				ofFlow.setIdleTimeOut(idleTimeout);
				OFController.getInstance().addFlow(dpId, ofFlow);
				deviceNode.addNode(DeviceNode.Directions.TO_LOCAL, endpoint, edgeNode);
			} else {
				OFFlow ofFlow = new OFFlow();
				ofFlow.setSrcMac(deviceMac);
				if (packet.getIpProto() != null && !packet.getIpProto().equals("*")) {
					ofFlow.setIpProto("" + retreivedNode.getEdges().get(0).getIpProtocol());
				}
				if(isMulticastorBroadcast(packet.getDstMac())) ofFlow.setDstMac(packet.getDstMac());
				ofFlow.setDstIp(retreivedNode.getValue().equals("*") ? "*" : packet.getDstIp());
				ofFlow.setEthType(packet.getEthType());
				ofFlow.setPriority(REACTIVE_LOCAL_FLOW_PRIORITY);
				ofFlow.setOfAction(OFFlow.OFAction.NORMAL);
				ofFlow.setIdleTimeOut(idleTimeout);
				OFController.getInstance().addFlow(dpId, ofFlow);
			}
			return;
		}

	}

	private String getEdgeNodeValue(int value) {
		if (value == -1) {
			return "*";
		}
		return "" + value;
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

	@Override
	public void complete() {

	}
}
