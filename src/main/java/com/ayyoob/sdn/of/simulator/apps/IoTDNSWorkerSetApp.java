package com.ayyoob.sdn.of.simulator.apps;

import com.ayyoob.sdn.of.simulator.Constants;
import com.ayyoob.sdn.of.simulator.SimPacket;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Paths;
import java.util.*;

public class IoTDNSWorkerSetApp implements ControllerApp{

	private static boolean enabled = false;
	private static String device;
	private static String gateway;
	private static Map<String, Set<String>> dnsMap = new HashMap<>();
	private static Set<String> icmpIps = new HashSet<>();
	private static Set<String> dnsIps = new HashSet<>();
	private static Set<String> ntpIps = new HashSet<>();
	private static String filename;
	private static String icmpFilename;
	private static String dnsFilename;
	private static String ntpFilename;

	@Override
	public void init(JSONObject jsonObject) {
		enabled = (Boolean) jsonObject.get("enabled");
		if (!enabled) {
			return;
		}

		device =( (String) jsonObject.get("device")).toLowerCase();
		gateway =( (String) jsonObject.get("gateway")).toLowerCase();

		String currentPath = Paths.get(".").toAbsolutePath().normalize().toString();

		File workingDirectory = new File(currentPath + File.separator + "result");
		if (!workingDirectory.exists()) {
			workingDirectory.mkdir();
		}
		filename = currentPath + File.separator + "result" + File.separator + device.replace(":","") + "-dnsworkers.csv";
		icmpFilename = currentPath + File.separator + "result" + File.separator + device.replace(":","") + "-icmpworker.csv";
		dnsFilename = currentPath + File.separator + "result" + File.separator + device.replace(":","") + "-dnsworker.csv";
		ntpFilename = currentPath + File.separator + "result" + File.separator + device.replace(":","") + "-ntpworker.csv";
	}

	@Override
	public void process(String dpId, SimPacket packet) {
		if (enabled) {
			if (packet.getDstMac().equals(device) && packet.getSrcMac().equals(gateway)  && packet.getdnsQname() != null
					&& packet.getDnsAnswers() != null && packet.getDnsAnswers().size() > 0) {
				Set<String> ips = dnsMap.get(packet.getdnsQname());
				if (ips != null) {
					ips.addAll(packet.getDnsAnswers());
					dnsMap.put(packet.getdnsQname(),ips);
				} else {
					ips = new HashSet<>();
					ips.addAll(packet.getDnsAnswers());
					dnsMap.put(packet.getdnsQname(),ips);
				}
			}

			if ((packet.getDstMac().equals(gateway) && packet.getSrcMac().equals(device)
					&& Constants.ICMP_PROTO.equals(packet.getIpProto())
					|| (packet.getDstMac().equals(device) && packet.getSrcMac().equals(gateway)
					&& Constants.ICMP_PROTO.equals(packet.getIpProto())))) {

				if (packet.getDstMac().equals(gateway)) {
					icmpIps.add(packet.getDstIp());
				} else {
					icmpIps.add(packet.getSrcIp());
				}
			}

			if (packet.getDstMac().equals(gateway) && packet.getSrcMac().equals(device)
					&& Constants.DNS_PORT.equals(packet.getDstPort())) {
				dnsIps.add(packet.getDstIp());
			}

			if (packet.getDstMac().equals(gateway) && packet.getSrcMac().equals(device)
					&& Constants.NTP_PORT.equals(packet.getDstPort())) {
				ntpIps.add(packet.getDstIp());
			}


		}
	}

	@Override
	public void complete() {
		if (enabled) {
			try {
				writeDns();
				writeNtpIps();
				writeDnsIps();
				writeIcmpIps();
			} catch (IOException e) {

			}
		}
	}

	private static void writeDns() throws IOException {
		File file = new File(filename);
		FileWriter writer = new FileWriter(file, true);
		System.out.println("Writing raw... ");

		for (String record: dnsMap.keySet()) {
			Set<String> ips = dnsMap.get(record);
			for (String ip : ips) {
				writer.write(record + "," + ip + "," + "\n");
			}
			writer.flush();
		}
		writer.flush();
		writer.close();
	}

	private static void writeIcmpIps() throws IOException {
		File file = new File(icmpFilename);
		FileWriter writer = new FileWriter(file, true);
		for (String ip : icmpIps) {
			writer.write(ip + "," + "\n");
		}
		writer.flush();
		writer.close();
	}

	private static void writeDnsIps() throws IOException {
		File file = new File(dnsFilename);
		FileWriter writer = new FileWriter(file, true);
		System.out.println("Writing raw... ");
		for (String ip : dnsIps) {
			writer.write(ip + "," + "\n");
		}
		writer.flush();
		writer.close();
	}

	private static void writeNtpIps() throws IOException {
		File file = new File(ntpFilename);
		FileWriter writer = new FileWriter(file, true);
		System.out.println("Writing raw... ");
		for (String ip : ntpIps) {
			writer.write(ip + "," + "\n");
		}
		writer.flush();
		writer.close();
	}

}
