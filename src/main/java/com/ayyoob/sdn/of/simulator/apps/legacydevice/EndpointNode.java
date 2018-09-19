package com.ayyoob.sdn.of.simulator.apps.legacydevice;

import java.util.List;

public class EndpointNode {
	String value;
	int id;
	List<EdgeNode> edges;
	int previousChecked = 0;

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
		id = value.hashCode();
	}

	public List<EdgeNode> getEdges() {
		return edges;
	}

	public void setEdges(List<EdgeNode> edges) {
		this.edges = edges;
	}

	public int getPreviousChecked() {
		return previousChecked;
	}

	public void setPreviousChecked(int previousChecked) {
		this.previousChecked = previousChecked;
	}

}
