package net.floodlightcontroller.unipi.maliciousflows;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowModFlags;
import org.projectfloodlight.openflow.protocol.OFFlowRemoved;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.Link;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.unipi.maliciousflows.model.Flow;
import net.floodlightcontroller.unipi.maliciousflows.web.IMaliciousFlowsQuarantineREST;
import net.floodlightcontroller.unipi.maliciousflows.web.MaliciousFlowsQuarantineWebRoutable;
import net.floodlightcontroller.util.FlowModUtils;

public class MaliciousFlowsQuarantine implements IOFMessageListener, IFloodlightModule, IMaliciousFlowsQuarantineREST {
    
    // rule timeouts
    private final static short IDLE_TIMEOUT = 30;
    private final static short HARD_TIMEOUT = 60;

    // IP and MAC address of the special switch
    private final static DatapathId SWITCH_DPID =  DatapathId.of("00:00:00:00:00:00:00:09");

    // available flows
    protected static ArrayList<Flow> flows = new ArrayList<>();

    protected IFloodlightProviderService floodlightProvider; // Reference to the provider
    protected IRestApiService restApiService; // Reference to the REST API service
    protected ILinkDiscoveryService linkService; // link discovery service
    protected IOFSwitchService switchService;   // switch service

    @Override
	public String getName() {
		return MaliciousFlowsQuarantine.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IMaliciousFlowsQuarantineREST.class);
        return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = 
            new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
        
        m.put(IMaliciousFlowsQuarantineREST.class, this);
        return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        l.add(ILinkDiscoveryService.class);
        l.add(IOFSwitchService.class);
        l.add(IRestApiService.class);
        return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        restApiService = context.getServiceImpl(IRestApiService.class);
        linkService = context.getServiceImpl(ILinkDiscoveryService.class);
        switchService = context.getServiceImpl(IOFSwitchService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);

        // add as REST interface
        restApiService.addRestletRoutable(new MaliciousFlowsQuarantineWebRoutable());
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        Flow flow = null;
        // possible messages
        switch (msg.getType()) {
            case FLOW_REMOVED:
                // malicious flow rule is expired, check if it must be refreshed
                OFFlowRemoved flowRemoved = (OFFlowRemoved) msg;
                Match match = flowRemoved.getMatch();

                // look if the flow is still marked
                flow = findFlow(match.get(MatchField.IPV4_SRC), match.get(MatchField.IPV4_DST));
                if (flow != null) {
                    System.out.printf("Refresh malicious flow redirection rule on {%s}\n", sw.getId());
                    redirectMaliciousFlow(sw, flow, null);
                    return Command.STOP;
                }
                break;

            case PACKET_IN:
                Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
                IPacket pkt = eth.getPayload();
                OFPacketIn pi = (OFPacketIn) msg;

                // check if the packet is IPv4
                if (pkt instanceof IPv4) {
                    System.out.println("Processing IPv4 packet from {" + sw.getId() + "}");
                    IPv4 ipPkt = (IPv4) pkt;

                    // get the flow
                    flow = findFlow(ipPkt.getSourceAddress(), ipPkt.getDestinationAddress());
                    // check if the traffic is marked
                    if (flow != null) {
                        System.out.printf("Setting up malicious flow redirection rule on {%s}\n", sw.getId());
                        // add/refresh the redirection rule
                        redirectMaliciousFlow(sw, flow, pi);

                        // if the packet is coming from the special switch we put it in quarantine
                        if (sw.getId().compareTo(SWITCH_DPID) == 0) {
                            flow.addPacket(msg);
                            System.out.println("Malicious packet collected: " + flow.toString());
                        }
                        // stop the chain
                        return Command.STOP;
                    }
                }

                break;

            default:
                System.err.println("Error: message type not valid.");
            
        }
        
        return Command.CONTINUE;
    }

    /**
     * methos used to set up a flow rule in the switch to redirect the traffic to the special switch 
     * if it belong to a marked flow 
     * @param sw specific switch
     * @param pi OpenFlow Packet-In
     * @param ipv4 IPv4 packet
     * @param flow marked flow
     */
    private void redirectMaliciousFlow(IOFSwitch sw, Flow flow, OFPacketIn pi) {
        // add the rule to redirect the traffic to the special router
        OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
        
        fmb.setIdleTimeout(IDLE_TIMEOUT)
            .setHardTimeout(HARD_TIMEOUT)
            .setPriority(FlowModUtils.PRIORITY_MAX);

        // set the flag to send an advertisment when the rule expire
        Set<OFFlowModFlags> flags = new HashSet<OFFlowModFlags>();
		flags.add(OFFlowModFlags.SEND_FLOW_REM);
        fmb.setFlags(flags);
		
        if (pi != null) {
            fmb.setBufferId(pi.getBufferId())
                .setXid(pi.getXid());
        }

        // match all the packet of the marked flow
        Match.Builder mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
            .setExact(MatchField.IPV4_DST, IPv4Address.of(flow.getServerIP()))
            .setExact(MatchField.IPV4_SRC, IPv4Address.of(flow.getClientIP()));
        
        // set the actions      
        OFActions actions = sw.getOFFactory().actions();
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();

        // chose the correct out port based on the specif case
        OFPort outPort = OFPort.of(1);  // default out-port

        // if we are the special switch we have to forward to the controller
        if (sw.getId().compareTo(SWITCH_DPID) == 0) {
            outPort = OFPort.CONTROLLER;
        } else {
            // search the out-port to the special switch
            Iterator<Link> links = linkService.getSwitchLinks().get(sw.getId()).iterator();
            while (links.hasNext()) {
                Link link = links.next();
                if (link.getDst().compareTo(SWITCH_DPID) == 0) {
                    outPort = link.getSrcPort();  
                    break;
                }
            }
        }
            
        // set the out port
        OFActionOutput output = actions.buildOutput()
                .setMaxLen(0xFFffFFff)
                .setPort(outPort)
                .build();
        actionList.add(output);
    
        fmb.setActions(actionList);
        fmb.setMatch(mb.build());

        // add the rule to the flow as record
        flow.setActiveRule(sw.getId(), fmb.build());

        sw.write(fmb.build());
    }


    // REST APIs

    /** 
     * method used to get the list of all the recorded marked flows
     * @return list of all the marked flows
    */
    @Override
    public List<Flow> getFlows() {
        return flows;
    }

    /** 
     * method used to get the size of the quarantine buffer specified
     * @param clientIP IPv4 address of the client
     * @param serverIP IPv4 address of the server
     * @return size of the quarantine buffer, -1 in case of error
    */
    @Override
    public Integer getQuarantineBufferSize(IPv4Address clientIP, IPv4Address serverIP) {
        // check if the flow exist
        Flow targetFlow = findFlow(clientIP, serverIP);
        if (targetFlow == null) {
            return -1;
        }

        return targetFlow.getBufferSize();
    }

    /** 
     * method used to change the size of the quarantine buffer specified
     * @param clientIP IPv4 address of the client
     * @param serverIP IPv4 address of the server
     * @param newSize new size of the array
     * @return response message to the REST API
    */
    @Override
    public String setQuarantineBufferSize(String flowId, Integer newSize) {
        // check if the siz is valid
        if (newSize == null || newSize < 1) 
            return "Error: size not valid!";
        
        // check if there is the specific flow
        Flow targetFlow = findFlow(flowId);
        if (targetFlow == null) {
            return "Error: Flow not found!";
        }
        
        // try to change the size
        try {
            targetFlow.changeBufferSize(newSize);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            return e.getMessage();
        }

        System.out.println("Update the flow: " + targetFlow);
        return "Ok";
    }

    /** 
     * method used to retrieve how many packets are in the quarantine buffer
     * of the specified flow
    * @param id flow ID
    * @return the number of buffered packets, -1 in case of error
    */
    @Override
    public Integer getNumberOfBufferedPackets(String id) {
        // check if the flow exist
        Flow targetFlow = findFlow(id);
        if (targetFlow == null) {
            return -1;
        }

        int result = -1;
        try {
            result = targetFlow.getNumberOfStoredPackets();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
    * methos used to create a new marked flow 
    * @param clientIP IPv4 address of the client
    * @param serverIP IPv4 address of the server
    * @return response message to the REST API
    */
    @Override
    public String markFlow(IPv4Address clientIP, IPv4Address serverIP) {
        // check if the flow already exist
        Flow targetFlow = findFlow(clientIP, serverIP);
        if (targetFlow != null)
            return "Error: Flow already marked!";

        // create the marked flow
        Flow newFlow = new Flow(clientIP.toString(), serverIP.toString());
        flows.add(newFlow);

        // send the rule to all the switches
        System.out.println("Setting redirection rule in all the switches...");
        Iterator<DatapathId> switches = switchService.getAllSwitchDpids().iterator();
        while(switches.hasNext()) {
            IOFSwitch sw = switchService.getSwitch(switches.next());
            redirectMaliciousFlow(sw, newFlow, null);
        }

        System.out.println("New flow marked " + newFlow);
        return "Ok";
    }

    /** 
     * method used to remove a marked flow
     * @param clientIP IPv4 address of the client
     * @param serverIP IPv4 address of the server
     * @param mode what to do with the packets in the quarantine buffer ("flush"/"clear")
     * @return response message to the REST API
    */
    @Override
    public String unmarkFlow(IPv4Address clientIP, IPv4Address serverIP, String mode) {
        // get the specific flow
        Flow targetFlow = findFlow(clientIP, serverIP);
        if (targetFlow == null)
            return "Error: Flow do not found!";
        if (!mode.equals("flush") && !mode.equals("clear"))
            return "Error: Mode not valid!";

        // unmark the flow
        OFMessage[] bufferedMessage = targetFlow.unmark(mode);
        flows.remove(targetFlow);
        System.out.printf("Flow %s -> %s unmarked (%s)\n", clientIP, serverIP, mode);

        // delete the rule from the switches
        Iterator<Map.Entry<DatapathId, OFMessage>> activeRules = targetFlow.getActiveRules().entrySet().iterator();
        while (activeRules.hasNext()) {
            Map.Entry<DatapathId, OFMessage> rule = activeRules.next();
            IOFSwitch sw = switchService.getActiveSwitch(rule.getKey());
            // create the delete flow message from the FlowMod message
            OFMessage message = FlowModUtils.toFlowDeleteStrict((OFFlowMod) rule.getValue());
            sw.write(message);
            System.out.println("Delete the rule from the switch {" + rule.getKey() + "}");
        }

        // check if we have to flush the quarantine buffer
        if (bufferedMessage != null) {
            // get iformation about the special switch
            IOFSwitch sw = switchService.getSwitch(SWITCH_DPID);
            if (sw == null) {
                return "Error: not able to get the special switch to flush the packets!";
            }

            System.out.println("Forwarding the packets in quarantine [" + bufferedMessage.length + "]");

            // forward all the packets in the quarantine buffer
            for (OFMessage msg : bufferedMessage) {
                OFPacketIn pi = (OFPacketIn) msg;

                OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
                pob.setBufferId(pi.getBufferId());
                pob.setInPort(OFPort.ANY);

                // set the actions 
                OFActions actions = sw.getOFFactory().actions();
                ArrayList<OFAction> actionList = new ArrayList<OFAction>();

                OFActionOutput output = actions.buildOutput()
                        .setMaxLen(0xFFffFFff)
                        .setPort(OFPort.of(1))
                        .build();
                actionList.add(output);

                pob.setActions(actionList);

                if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
                    byte[] packetData = pi.getData();
                    pob.setData(packetData);
                }

                sw.write(pob.build());
            }
        }
        
        return "Ok";
    }

    /**
     * Look-up for a marked flow searching by client IP and server IP
     * @param clientIP IPv4 address of the client
     * @param serverIP IPv4 address of the server
     * @return the Flow or null if it is not found
     */
    private Flow findFlow(IPv4Address clientIP, IPv4Address serverIP) {
        for (Flow flow: flows) {
            if (IPv4Address.of(flow.getClientIP()).compareTo(clientIP) == 0 &&
                IPv4Address.of(flow.getServerIP()).compareTo(serverIP) == 0) {
                return flow;
            }
        }
        return null;
    }

    /**
     * Look-up for a marked flow searching by ID
     * @param id flow ID
     * @return the Flow or null if it is not found
     */
    private Flow findFlow(String id) {
        for (Flow flow: flows) {
            if (flow.getId().toString().equals(id)) {
                return flow;
            }
        }
        return null;
    }
}
