package net.floodlightcontroller.unipi.maliciousflows.web;

import java.io.IOException;
import java.util.List;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.floodlightcontroller.unipi.maliciousflows.model.Flow;

public class FlowsResource extends ServerResource {
    
    @Get("json")
    public List<Flow> getFlows() {
        IMaliciousFlowsQuarantineREST mfq = (IMaliciousFlowsQuarantineREST) getContext().getAttributes().get(IMaliciousFlowsQuarantineREST.class.getCanonicalName());

        return mfq.getFlows();
    }

    @Post("json")
    public String configureFlow(String fmJson) {
        // check if the payloaded is provided
        if (fmJson == null) {
            return new String("No attributes");
        }

        // expected parameters
        IPv4Address clientIP = null;
        IPv4Address serverIP = null;
        String droppingMode = null;

        // parse the JSON input
        ObjectMapper mapper = new ObjectMapper();
        try {
            JsonNode root = mapper.readTree(fmJson);

            // check the parameter
            JsonNode client = root.get("client");
            if (client != null && !client.isNull()) {
                clientIP = IPv4Address.of(client.asText());
            }
            JsonNode server = root.get("server");
            if (server != null && !server.isNull()) {
                serverIP = IPv4Address.of(server.asText());
            }
            JsonNode mode = root.get("mode");
            if (mode != null && !mode.isNull()) {
                droppingMode = mode.asText();
            }
            
        } catch (IllegalArgumentException | IOException e) {
            return e.getMessage();
        } 

        // check IPv4b format
        
        
        // check which command must be call
        IMaliciousFlowsQuarantineREST mfq = (IMaliciousFlowsQuarantineREST) getContext().getAttributes().get(IMaliciousFlowsQuarantineREST.class.getCanonicalName());
        if (droppingMode != null)
            return mfq.unmarkFlow(clientIP, serverIP, droppingMode);
        
        return mfq.markFlow(clientIP, serverIP);
    }
}
