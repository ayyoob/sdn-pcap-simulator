package com.ayyoob.sdn.of.simulator.apps.attackdetector;

import com.ayyoob.sdn.of.simulator.OFFlow;
import com.ayyoob.sdn.of.simulator.SimPacket;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class EntropyHold {
	OFFlow ofFlow;
	Map<String, Set<String>> srcMap = new HashMap<>();
	Map<String, Set<String>> dstMap = new HashMap<>();

	Map<String, Set<String>> prevsrcMap = new HashMap<>();
	Map<String, Set<String>> prevdstMap = new HashMap<>();

	public EntropyHold(OFFlow ofFlow) {
		this.ofFlow = ofFlow;
	}

	private EntropyHoldData prevEntropyHoldData = new EntropyHoldData();

	public OFFlow getOfFlow() {
		return ofFlow;
	}

	public void addFlow(SimPacket simPacket) {
		if (srcMap.containsKey(simPacket.getSrcIp())) {
			srcMap.get(simPacket.getSrcIp()).add(simPacket.getSrcPort());
		} else {
			srcMap.put(simPacket.getSrcIp(), new HashSet<>());
			srcMap.get(simPacket.getSrcIp()).add(simPacket.getSrcPort());
		}

		if (dstMap.containsKey(simPacket.getDstIp())) {
			dstMap.get(simPacket.getDstIp()).add(simPacket.getDstPort());
		} else {
			dstMap.put(simPacket.getDstIp(), new HashSet<>());
			dstMap.get(simPacket.getDstIp()).add(simPacket.getDstPort());
		}

	}

	public Map<String, Set<String>> getSrcMap() {
		return prevsrcMap;
	}

	public Map<String, Set<String>> getDstMap() {
		return prevdstMap;
	}



	public EntropyHoldData getPrevEntropyHoldData() {
		return prevEntropyHoldData;
	}

	public void caculateCost() {
		int uniqueSrcTuple = 0;
		Set<String> srcPort = new HashSet<>();
		for (String srcIp : srcMap.keySet()) {
			srcPort.addAll(srcMap.get(srcIp));
			uniqueSrcTuple = uniqueSrcTuple + srcMap.get(srcIp).size();
		}

		int uniqueDstTuple = 0;
		Set<String> dstPort = new HashSet<>();
		for (String dstIp : dstMap.keySet()) {
			dstPort.addAll(dstMap.get(dstIp));
			uniqueDstTuple = uniqueDstTuple + dstMap.get(dstIp).size();
		}
		EntropyHoldData entropyHoldData = new EntropyHoldData();
		entropyHoldData.SrcIpSize = srcMap.keySet().size();
		entropyHoldData.SrcPortSize = srcPort.size();
		entropyHoldData.SrcIpPortSize = uniqueSrcTuple;
		entropyHoldData.DstIpSize = dstMap.keySet().size();
		entropyHoldData.DstPortSize = dstPort.size();
		entropyHoldData.DstIpPortSize = uniqueDstTuple;

		prevEntropyHoldData =  entropyHoldData;
		prevsrcMap = srcMap;
		prevdstMap = dstMap;
		srcMap = new HashMap<>();
		dstMap = new HashMap<>();

	}

}
