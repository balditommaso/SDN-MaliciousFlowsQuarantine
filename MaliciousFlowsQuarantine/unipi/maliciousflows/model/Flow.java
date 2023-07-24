package net.floodlightcontroller.unipi.maliciousflows.model;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.types.DatapathId;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * Flow is the instance of a data-flow from a client to a server 
 * that has been marked as malicious. 
 */
public class Flow {

    private final UUID id;
    private final String clientIP;
    private final String serverIP;
    private int bufferSize;

    @JsonIgnore
    private QuarantineBuffer<OFMessage> quarantineBuffer;
    @JsonIgnore
    private Map<DatapathId, OFMessage> activeRules;
    
    public Flow(String clientIP, String serverIP) {
        this.id = UUID.randomUUID();
        this.clientIP = clientIP;
        this.serverIP = serverIP;
        this.bufferSize = 20;

        this.quarantineBuffer = new QuarantineBuffer<OFMessage>(bufferSize, OFMessage.class);
        this.activeRules = new HashMap<>();
    }

    public UUID getId() {
        return id;
    }

    public String getClientIP() {
        return clientIP;
    }

    public String getServerIP() {
        return serverIP;
    }

    public int getBufferSize() {
        return bufferSize;
    }

    @JsonIgnore
    public Map<DatapathId, OFMessage> getActiveRules() {
        return activeRules;
    }

    @JsonIgnore
    public int getNumberOfStoredPackets() throws IllegalAccessException {
        return quarantineBuffer.getNumberOfStoredObjects();
    }

    public synchronized OFMessage[] unmark(String mode) {
        // check the parameter
        if (!mode.equals("flush") && !mode.equals("clear"))
            throw new IllegalArgumentException("Not valid mode");

        // handle the packets in the buffer
        OFMessage[] quarantinePackets = null;
        if (mode.equals("flush")) {
            quarantinePackets =  quarantineBuffer.getContents();
        }

        // drop the buffer
        quarantineBuffer = null;
        return quarantinePackets;
    }

    public synchronized void changeBufferSize(int newBufferSize) throws IllegalAccessException {
        // change the size
        try {
            quarantineBuffer.changeBufferSize(newBufferSize);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            return;
        }
        bufferSize = newBufferSize;
    }

    public synchronized void addPacket(OFMessage sample) {
        quarantineBuffer.add(sample);
    }

    public synchronized void setActiveRule(DatapathId swID, OFMessage msg) {
            activeRules.put(swID, msg);
    }

    public synchronized void deleteActiveRule(DatapathId swID) {
        if (activeRules.containsKey(swID)) {
            activeRules.remove(swID);
        }
    }

    @Override
    public String toString() {
        return "[clientIP=" + clientIP + ", serverIP=" + serverIP + "], buffer = " + quarantineBuffer.getNumberOfStoredObjects() + "/" + bufferSize;
    }

}
