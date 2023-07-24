package net.floodlightcontroller.unipi.maliciousflows.web;

import java.util.List;

import org.projectfloodlight.openflow.types.IPv4Address;

import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.unipi.maliciousflows.model.Flow;

public interface IMaliciousFlowsQuarantineREST extends IFloodlightService {
    
    public List<Flow> getFlows();

    public Integer getQuarantineBufferSize(IPv4Address clientIP, IPv4Address serverIP);

    public String setQuarantineBufferSize(String flowId, Integer newSize);

    public Integer getNumberOfBufferedPackets(String id);

    public String markFlow(IPv4Address clientIP, IPv4Address serverIP);

    public String unmarkFlow(IPv4Address clientIP, IPv4Address serverIP, String mode);

}
