package com.ayyoob.sdn.of.simulator.apps.legacydevice;

public class EdgeNode {
	// -1 indicates wildcarded;
	private int ethType = -1;
	private int ipProtocol = -1;
	private int sourcePort = -1;
	private int destPort = -1;
	private int icmpCode = -1;
	private int icmpType = -1;

	public int getEthType() {
		return ethType;
	}

	public void setEthType(int ethType) {
		this.ethType = ethType;
	}

	public int getIpProtocol() {
		return ipProtocol;
	}

	public void setIpProtocol(int ipProtocol) {
		this.ipProtocol = ipProtocol;
	}

	public int getSourcePort() {
		return sourcePort;
	}

	public void setSourcePort(int sourcePort) {
		this.sourcePort = sourcePort;
	}

	public int getDestPort() {
		return destPort;
	}

	public void setDestPort(int destPort) {
		this.destPort = destPort;
	}

	public int getIcmpCode() {
		return icmpCode;
	}

	public void setIcmpCode(int icmpCode) {
		this.icmpCode = icmpCode;
	}

	public int getIcmpType() {
		return icmpType;
	}

	public void setIcmpType(int icmpType) {
		this.icmpType = icmpType;
	}

	public boolean isMatching(EdgeNode edgeNode) {
		return this.ethType == edgeNode.getEthType() && this.ipProtocol == edgeNode.getIpProtocol()
				&& (this.sourcePort == -1 || this.sourcePort == edgeNode.getSourcePort())
				&& (this.destPort == -1 || this.destPort == edgeNode.getDestPort())
				&& (this.icmpCode == -1 || this.icmpCode == edgeNode.icmpCode)
				&& (this.icmpType == -1 ||this.icmpType == edgeNode.icmpType);
	}

	public boolean isAbsoluteMatching(EdgeNode edgeNode) {
		return this.ethType == edgeNode.getEthType() && this.ipProtocol == edgeNode.getIpProtocol()
				&& this.sourcePort == edgeNode.getSourcePort()
				&& this.destPort == edgeNode.getDestPort()
				&& this.icmpCode == edgeNode.icmpCode
				&& this.icmpType == edgeNode.icmpType;
	}

	@Override
	public String toString() {
		return "eth_type:" + getValue(ethType) + ",ip_proto:" + getValue(ipProtocol) + ",source_port:" + getValue(sourcePort)
				+ ",dest_port:" + getValue(destPort) + ",icmp_code:" + getValue(icmpCode)  + ",icmp_type:" + getValue(icmpType) ;
	}

	private String getValue(int x) {
		if (x == -1) return "*";
		else return "" +x;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		EdgeNode edgeNode = (EdgeNode) o;

		if (ethType != edgeNode.ethType) return false;
		if (ipProtocol != edgeNode.ipProtocol) return false;
		if (sourcePort != edgeNode.sourcePort) return false;
		if (destPort != edgeNode.destPort) return false;
		if (icmpCode != edgeNode.icmpCode) return false;
		return icmpType == edgeNode.icmpType;
	}

	@Override
	public int hashCode() {
		int result = ethType;
		result = 31 * result + ipProtocol;
		result = 31 * result + sourcePort;
		result = 31 * result + destPort;
		result = 31 * result + icmpCode;
		result = 31 * result + icmpType;
		return result;
	}

	public EdgeNode clone() {
		EdgeNode edgeNode = new EdgeNode();
		edgeNode.ethType = this.ethType;
		edgeNode.ipProtocol = this.ipProtocol;
		edgeNode.destPort = this.destPort;
		edgeNode.sourcePort = this.sourcePort;
		edgeNode.icmpCode = this.icmpCode;
		edgeNode.icmpType = this.icmpType;
		return  edgeNode;
	}
}
