package com.ayyoob.sdn.of.simulator.apps.attackdetector;

import com.ayyoob.sdn.of.simulator.OFFlow;

import java.util.HashMap;
import java.util.Map;

public class EntropyData {

	Map<String, Integer> srcIp = new HashMap();
	Map<String, Integer> dstIp = new HashMap();
	Map<String, Integer> srcPort = new HashMap();
	Map<String, Integer> dstPort = new HashMap();
	Map<String, Integer> icmpCode = new HashMap();
	Map<String, Integer> icmpType = new HashMap();

	int srcIpLength = 0;
	int dstIpLength = 0;
	int srcPortLength = 0;
	int dstPortLength = 0;
	int icmpCodeLength = 0;
	int icmpTypeLength = 0;


	public void clearData() {
		srcIp.clear();
		dstIp.clear();
		srcPort.clear();
		dstPort.clear();
		icmpCode.clear();
		icmpType.clear();

		srcIpLength = 0;
		dstIpLength = 0;
		srcPortLength = 0;
		dstPortLength = 0;
		icmpCodeLength = 0;
		icmpTypeLength = 0;

	}

	public void addSrcIp(String value) {
		if (value == null) {
			return;
		}
		if (!srcIp.containsKey(value)) {
			srcIp.put(value, 0);
		}
		srcIp.put(value, srcIp.get(value) + 1);
		srcIpLength++;
	}

	public void addDstIp(String value) {
		if (value == null) {
			return;
		}
		if (!dstIp.containsKey(value)) {
			dstIp.put(value, 0);
		}
		dstIp.put(value, dstIp.get(value) + 1);
		dstIpLength++;
	}

	public void addSrcPort(String value) {
		if (value == null) {
			return;
		}
		if (!srcPort.containsKey(value)) {
			srcPort.put(value, 0);
		}
		srcPort.put(value, srcPort.get(value) + 1);
		srcPortLength++;
	}

	public void addDstPort(String value) {
		if (value == null) {
			return;
		}
		if (!dstPort.containsKey(value)) {
			dstPort.put(value, 0);
		}
		dstPort.put(value, dstPort.get(value) + 1);
		dstPortLength++;
	}

	public void addIcmpCode(String value) {
		if (value == null) {
			return;
		}
		if (!icmpCode.containsKey(value)) {
			icmpCode.put(value, 0);
		}
		icmpCode.put(value, icmpCode.get(value) + 1);
		icmpCodeLength++;
	}

	public void addIcmpType(String value) {
		if (value == null) {
			return;
		}
		if (!icmpType.containsKey(value)) {
			icmpType.put(value, 0);
		}
		icmpType.put(value, icmpType.get(value) + 1);
		icmpTypeLength++;
	}


	public String calculateShannonEntropy() {
		String entropy = "," +
				getEntropy(srcIp, srcIpLength) + "," +
				getEntropy(dstIp, dstIpLength) + "," +
				getEntropy(srcPort, srcPortLength) + "," +
				getEntropy(dstPort, dstPortLength)  + "," +
				getEntropy(icmpCode, icmpCodeLength) + "," +
				getEntropy(icmpType, icmpTypeLength);

		return  entropy;
	}

	//https://www.xycoon.com/normalized_entropy.htm
	private double getEntropy(Map<String, Integer> map, int length) {

//		if ((map.keySet().size()) <= 1) {
//			return 0;
//		}
		if ((map.keySet().size()) == 0) {
			return -1;
		}
		// calculate the entropy
		Double result = 0.0;
		for (String sequence : map.keySet()) {
			Double frequency = (double) map.get(sequence) / length;
			result -= frequency * (Math.log(frequency) / Math.log(2));
//			result -= frequency * (Math.log(frequency));
		}

//		return result/(Math.log(map.keySet().size()));
		return result;
	}
}
