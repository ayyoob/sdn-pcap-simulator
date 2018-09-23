package com.ayyoob.sdn.of.simulator.apps.legacydevice;

import java.util.*;

public class DeviceNode {

	ArrayList<EndpointNode>[] root = new ArrayList[4];
	String value;
	int numberOFEdgeNode;

	public DeviceNode(String value) {
		this.value = value;
		for (int i = 0; i <4; i++) {
			root[i] = new ArrayList<EndpointNode>();
		}
	}

	public enum Directions {
		TO_INTERNET(0),
		FROM_INTERNET(1),
		TO_LOCAL(2),
		FROM_LOCAL(3);

		private final int value;
		private Directions(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}
	}

	public void removeNode(Directions direction, String endpoint) {
		List<EndpointNode> endpointNodes = getEndpointNodes(direction);
		for (int i = 0; i < endpointNodes.size(); i++) {
			if (endpointNodes.get(i).getValue().equals(endpoint)) {
				EndpointNode endpointNode = endpointNodes.remove(i);
				numberOFEdgeNode = numberOFEdgeNode - endpointNode.getEdges().size();
				break;
			}
		}
	}

	public EndpointNode getEndpointNode(Directions direction, String endpoint) {
		List<EndpointNode> endpointNodes = getEndpointNodes(direction);
		for (int i = 0; i < i++; endpointNodes.size()) {
			if (endpointNodes.get(i).getValue().equals(endpoint)) {
				return endpointNodes.get(i);
			}
		}
		return  null;
	}

	public void addNode(Directions direction, String endpoint, EdgeNode edgeNode) {
		List<EndpointNode> endpointNodes = getEndpointNodes(direction);
		for (EndpointNode endpointNode : endpointNodes) {
			if (endpointNode.getValue().equals(endpoint)) {
				endpointNode.getEdges().add(edgeNode);
				numberOFEdgeNode++;
				return;
			}
		}
		EndpointNode endpointNode = new EndpointNode();
		endpointNode.setValue(endpoint);
		List<EdgeNode> edges  = new ArrayList<>();
		edges.add(edgeNode);
		numberOFEdgeNode++;
		endpointNode.setEdges(edges);
		int index = 0;
		for (EndpointNode ed : endpointNodes) {
			if (ed.getId() > endpointNode.getId()) {
				break;
			}
			index++;
		}
		endpointNodes.add(index, endpointNode);
	}

	public void addNode(Directions direction, String endpoint, List<EdgeNode> edgeNodes) {
		List<EndpointNode> endpointNodes = getEndpointNodes(direction);
		for (EndpointNode endpointNode : endpointNodes) {
			if (endpointNode.getValue().equals(endpoint)) {
				endpointNode.getEdges().addAll(edgeNodes);
				numberOFEdgeNode = numberOFEdgeNode + edgeNodes.size();
				return;
			}
		}
		EndpointNode endpointNode = new EndpointNode();
		endpointNode.setValue(endpoint);
		numberOFEdgeNode = numberOFEdgeNode + edgeNodes.size();
		endpointNode.setEdges(edgeNodes);
		int index = 0;
		for (EndpointNode ed : endpointNodes) {
			if (ed.getId() > endpointNode.getId()) {
				break;
			}
			index++;
		}
		endpointNodes.add(index, endpointNode);
	}

	public List<EdgeNode> getEdgeNodes(Directions direction, String endpoint) {
		ArrayList<EndpointNode> endpointNodes = getEndpointNodes(direction);
		int id = endpoint.hashCode();
		int index = binaryHelper(id, endpointNodes, 0, endpointNodes.size()-1);
		if (index == -1) {
			return null;
		}

		if (!endpointNodes.get(index).getValue().equals(endpoint)) {
			System.out.println("HASH CONFLICT HAPPENING...");
		} else {
			return endpointNodes.get(index).getEdges();
		}
		return null;
	}

	private int binaryHelper(int value, ArrayList<EndpointNode> endpointNodes, int leftIndex, int rightIndex) {
		int currentIndex = leftIndex + ((rightIndex - leftIndex)/2);
		if (rightIndex >= leftIndex) {
			if (endpointNodes.get(currentIndex).getId() == value) {
				return currentIndex;
			}
			if (value > endpointNodes.get(currentIndex).getId()) {
				leftIndex = currentIndex + 1;
				return binaryHelper(value, endpointNodes, leftIndex, rightIndex);
			} else {
				rightIndex = currentIndex - 1;
				return binaryHelper( value, endpointNodes, leftIndex, rightIndex);
			}
		}

		return -1;
	}

	public ArrayList<EndpointNode> getEndpointNodes(Directions direction) {
		return root[direction.getValue()];
	}

	public EndpointNode getNode(Directions direction, String endpoint, EdgeNode edgeNode) {
		List<EndpointNode> endpointNodes = getEndpointNodes(direction);
		for (EndpointNode endpointNode : endpointNodes) {
			if (endpointNode.getValue().equals(endpoint) || (isIp(endpoint) && endpointNode.getValue().equals("*"))) {
				for (EdgeNode edge : endpointNode.getEdges()) {
					if (edge.isMatching(edgeNode)) {
						EndpointNode ed = new EndpointNode();
						ed.setValue(endpointNode.getValue());
						List<EdgeNode> edges  = new ArrayList<>();
						edges.add(edge);
						ed.setEdges(edges);
						return ed;
					}
				}
			}
		}
		return null;
	}

	public int getDirectionEdgeCount(Directions direction) {
		int count = 0;
		List<EndpointNode> endpointNodes = getEndpointNodes(direction);
		for (EndpointNode endpointNode : endpointNodes) {
			count = count + endpointNode.getEdges().size();
		}
		return count;
	}

	public boolean isEndpointNodeExist(Directions direction, String endpoint) {
		List<EndpointNode> endpointNodes = getEndpointNodes(direction);
		for (EndpointNode endpointNode : endpointNodes) {
			if (endpointNode.getValue().equals(endpoint)) {
				return true;
			}
		}
		return false;
	}

	public EndpointNode getAbsoluteMatchingEndpointNode(Directions direction, String endpoint, EdgeNode edgeNode) {
		List<EndpointNode> endpointNodes = getEndpointNodes(direction);
		for (EndpointNode endpointNode : endpointNodes) {
			if (endpointNode.getValue().equals(endpoint)) {
				for (EdgeNode edge : endpointNode.getEdges()) {
					if (edge.isAbsoluteMatching(edgeNode)) {
						EndpointNode ed = new EndpointNode();
						ed.setValue(endpointNode.getValue());
						List<EdgeNode> edges  = new ArrayList<>();
						edges.add(edge);
						ed.setEdges(edges);
						return ed;
					}
				}
			}
		}
		return null;
	}

	public EndpointNode getMatchingEndpointNode(Directions direction, String endpoint, EdgeNode edgeNode) {
		List<EndpointNode> endpointNodes = getEndpointNodes(direction);
		for (EndpointNode endpointNode : endpointNodes) {
			if (endpointNode.getValue().equals(endpoint)) {
				for (EdgeNode edge : endpointNode.getEdges()) {
					if (edge.isMatching(edgeNode)) {
						EndpointNode ed = new EndpointNode();
						ed.setValue(endpointNode.getValue());
						List<EdgeNode> edges  = new ArrayList<>();
						edges.add(edge);
						ed.setEdges(edges);
						return ed;
					}
				}
			}
		}
		return null;
	}

	public String getNodeString() {
		String graph = value + "\n";
		graph = graph  + getDirectionNodes(Directions.TO_INTERNET) + "\n";
		graph = graph  + getDirectionNodes(Directions.FROM_INTERNET) + "\n";
		graph = graph  + getDirectionNodes(Directions.TO_LOCAL) + "\n";
		graph = graph  + getDirectionNodes(Directions.FROM_LOCAL) + "\n";
		return graph;
	}

	private String getDirectionNodes(Directions directions) {
		String direction = "\t" + directions.toString() + "\n";
		List<EndpointNode> endpointNodes = getEndpointNodes(directions);
		if (endpointNodes.size() > 0) {
			for (EndpointNode endpointNode : endpointNodes) {
				String endpoint = "\t\t" + endpointNode.getValue() + "\n";
				for (EdgeNode edgeNode : endpointNode.getEdges()) {
					endpoint = endpoint + "\t\t\t" + edgeNode.toString() + "\n";
				}
				direction = direction + endpoint;
			}
		}
		return direction;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	//TODO simple method to test this.
	private boolean isIp(String endpoint) {
		String ip = endpoint.replace(":", "").replace(".", "");
		try {
			int x = Integer.parseInt(endpoint);
			return true;
		} catch (NumberFormatException e) {
			try {
				int x = Integer.parseInt(endpoint, 16);
				return true;
			} catch (NumberFormatException ex) {
				return false;
			}

		}
	}
}
