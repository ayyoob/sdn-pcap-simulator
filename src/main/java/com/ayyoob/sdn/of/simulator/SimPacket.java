package com.ayyoob.sdn.of.simulator;

import java.util.List;

public class SimPacket {

    private long size;
    private String srcMac;
    private String dstMac;
    private String ethType;
    private String srcIp;
    private String dstIp;
    private String ipProto;
    private String srcPort;
    private String dstPort;
    private byte[] header;
    private byte[] data;
    private String dnsQname;
    private Flag tcpFlag;

    public enum Flag {
        SYN,
        SYN_ACK,
        OTHER
    }

    public String isDnsQname() {
        return dnsQname;
    }

    public void setDnsQname(String dnsQname) {
        this.dnsQname = dnsQname;
    }

    public List<String> getDnsAnswers() {
        return dnsAnswers;
    }

    public void setDnsAnswers(List<String> dnsAnswers) {
        this.dnsAnswers = dnsAnswers;
    }

    private List<String> dnsAnswers;
    private long timestamp;

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public long getSize() {
        return size;
    }

    public void setSize(long size) {
        this.size = size;
    }

    public String getSrcMac() {
        return srcMac;
    }

    public void setSrcMac(String srcMac) {
        this.srcMac = srcMac;
    }

    public String getDstMac() {
        return dstMac;
    }

    public void setDstMac(String dstMac) {
        this.dstMac = dstMac;
    }

    public String getEthType() {
        return ethType;
    }

    public void setEthType(String ethType) {
        this.ethType = ethType;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }

    public String getDstIp() {
        return dstIp;
    }

    public void setDstIp(String dstIp) {
        this.dstIp = dstIp;
    }

    public void setIpProto(String ipProto) {
        this.ipProto = ipProto;
    }

    public String getIpProto() {
        return ipProto;
    }

    public String getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(String srcPort) {
        this.srcPort = srcPort;
    }

    public String getDstPort() {
        return dstPort;
    }

    public void setDstPort(String dstPort) {
        this.dstPort = dstPort;
    }

    public byte[] getHeader() {
        return header;
    }

    public void setHeader(byte[] header) {
        this.header = header;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public Flag getTcpFlag() {
        return tcpFlag;
    }

    public void setTcpFlag(boolean syn, boolean ack) {
        tcpFlag = Flag.OTHER;
        if (syn) {
            tcpFlag = Flag.SYN;
            if (ack) {
                tcpFlag = Flag.SYN_ACK;
            }
        }
    }

    public void print() {
        System.out.println("size, srcMac, dstMac, ethType, srcIp, dstIp, ipProto, srcPort, dstPort,timestamp");
        System.out.println(size + "," + srcMac + "," + dstMac + "," + ethType + "," + srcIp + "," + dstIp
                + "," + ipProto + "," + srcPort + "," + dstPort + "," + timestamp);
    }

    public String getPacketInfo() {
        return size + "," + srcMac + "," + dstMac + "," + ethType + "," + srcIp + "," + dstIp
                + "," + ipProto + "," + srcPort + "," + dstPort + "," + timestamp;
    }
}
