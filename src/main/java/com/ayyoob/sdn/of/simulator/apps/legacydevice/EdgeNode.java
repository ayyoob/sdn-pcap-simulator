package com.ayyoob.sdn.of.simulator.apps.legacydevice;

import com.ayyoob.sdn.of.simulator.Constants;

public class EdgeNode {
	// -1 indicates wildcarded;
	private int ethType = -1;
	private int ipProtocol = -1;
	private int sourcePortStart = Constants.MIN_PORT;
	private int sourcePortEnd = Constants.MAX_PORT;
	private int destPortStart = Constants.MIN_PORT;
	private int destPortEnd = Constants.MAX_PORT;
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

	public int getSourcePortStart() {
		return sourcePortStart;
	}

	public void setSourcePortStart(int sourcePortStart) {
		this.sourcePortStart = sourcePortStart;
	}

	public int getSourcePortEnd() {
		return sourcePortEnd;
	}

	public void setSourcePortEnd(int sourcePortEnd) {
		this.sourcePortEnd = sourcePortEnd;
	}

	public int getDestPortStart() {
		return destPortStart;
	}

	public void setDestPortStart(int destPortStart) {
		this.destPortStart = destPortStart;
	}

	public int getDestPortEnd() {
		return destPortEnd;
	}

	public void setDestPortEnd(int destPortEnd) {
		this.destPortEnd = destPortEnd;
	}

	public void setDestPort(int port) {
		this.destPortStart = port;
		this.destPortEnd = port;

		//TODO temp fix for dhcp range
//		if (port == 67) {
//			this.sourcePortStart = 0;
//		}
//		if (port == 137) {
//			this.sourcePortStart = 0;
//		}
//		if (port == 138) {
//			this.sourcePortStart = 0;
//		}
	}

	public void setSourcePort(int port) {
		this.sourcePortStart = port;
		this.sourcePortEnd = port;

		//TODO temp fix for dhcp range
//		if (port == 67) {
//			this.destPortStart = 0;
//		}
//		if (port == 137) {
//			this.destPortStart = 0;
//		}
//		if (port == 138) {
//			this.destPortStart = 0;
//		}


	}

	public boolean isMatching(EdgeNode edgeNode) {
		return this.ethType == edgeNode.getEthType() && this.ipProtocol == edgeNode.getIpProtocol()
				&& (this.getSourcePortStart() <= edgeNode.getSourcePortStart())
				&& (this.getSourcePortEnd() >= edgeNode.getSourcePortEnd())
				&& (this.getDestPortStart() <= edgeNode.getDestPortStart())
				&& (this.getDestPortEnd() >= edgeNode.getDestPortEnd())
				&& (this.icmpCode == -1 || this.icmpCode == edgeNode.icmpCode)
				&& (this.icmpType == -1 ||this.icmpType == edgeNode.icmpType);
	}

	public boolean isAbsoluteMatching(EdgeNode edgeNode) {
		return this.ethType == edgeNode.getEthType() && this.ipProtocol == edgeNode.getIpProtocol()
				&& this.sourcePortStart == edgeNode.getSourcePortStart()
				&& this.sourcePortEnd == edgeNode.getSourcePortEnd()
				&& this.destPortStart == edgeNode.getDestPortStart()
				&& this.destPortEnd == edgeNode.getDestPortEnd()
				&& this.icmpCode == edgeNode.icmpCode
				&& this.icmpType == edgeNode.icmpType;
	}

	@Override
	public String toString() {
		return "eth_type:" + getValue(ethType) + ",ip_proto:" + getValue(ipProtocol)
				+ ",source_port_range:(" + getValue(sourcePortStart)  + "," + getValue(sourcePortEnd)
				+ "),dest_port_range:(" + getValue(destPortStart) + "," + getValue(destPortEnd)
				+ "),icmp_code:" + getValue(icmpCode)  + ",icmp_type:" + getValue(icmpType) ;
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
		if (sourcePortStart != edgeNode.sourcePortStart) return false;
		if (destPortStart != edgeNode.destPortStart) return false;
		if (sourcePortEnd != edgeNode.sourcePortEnd) return false;
		if (destPortEnd != edgeNode.destPortEnd) return false;
		if (icmpCode != edgeNode.icmpCode) return false;
		return icmpType == edgeNode.icmpType;
	}

	@Override
	public int hashCode() {
		int result = ethType;
		result = 31 * result + ipProtocol;
		result = 31 * result + sourcePortStart;
		result = 31 * result + destPortStart;
		result = 31 * result + sourcePortEnd;
		result = 31 * result + destPortEnd;
		result = 31 * result + icmpCode;
		result = 31 * result + icmpType;
		return result;
	}

	public EdgeNode clone() {
		EdgeNode edgeNode = new EdgeNode();
		edgeNode.ethType = this.ethType;
		edgeNode.ipProtocol = this.ipProtocol;
		edgeNode.destPortStart = this.destPortStart;
		edgeNode.destPortEnd= this.destPortEnd;
		edgeNode.sourcePortStart = this.sourcePortStart;
		edgeNode.sourcePortEnd = this.sourcePortEnd;
		edgeNode.icmpCode = this.icmpCode;
		edgeNode.icmpType = this.icmpType;
		return  edgeNode;
	}
}
