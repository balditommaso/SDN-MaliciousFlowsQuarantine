package net.floodlightcontroller.unipi.maliciousflows.web;

import java.io.IOException;

import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class QuarantineBufferResource extends ServerResource {
    
    @Get("json")
    public int getQuarantineBufferSize() {
        IMaliciousFlowsQuarantineREST mfq = (IMaliciousFlowsQuarantineREST) getContext().getAttributes().get(IMaliciousFlowsQuarantineREST.class.getCanonicalName());
        String flowId = (String) getRequestAttributes().get("id");
        // check the parameters
        if (flowId == null) {
            System.err.println("Error: Not valid parametes!");
            return -1;
        }
        
        return mfq.getNumberOfBufferedPackets(flowId);
    }

    @Post("json")
    public String configureBuffer(String fmJson) {
        String flowId = (String) getRequestAttributes().get("id");
        // check the parameters
        if (flowId == null) {
            System.err.println("Error: Not valid parametes!");
            return new String("No attributes");
        }
        
        // check if the payload is provided
        if (fmJson == null) {
            return new String("No attributes");
        }

        Integer newBufferSize = null;
        // parse the JSON input
        ObjectMapper mapper = new ObjectMapper();
        try {
            JsonNode root = mapper.readTree(fmJson);

            JsonNode sizeNode = root.get("size");
            if (sizeNode != null && !sizeNode.isNull()) {
                newBufferSize = Integer.parseInt(sizeNode.asText());
            }
            
        } catch (IllegalArgumentException | IOException e) {
            return e.getMessage();
        } 

        // check which command must be call
        IMaliciousFlowsQuarantineREST mfq = (IMaliciousFlowsQuarantineREST) getContext().getAttributes().get(IMaliciousFlowsQuarantineREST.class.getCanonicalName());
        return mfq.setQuarantineBufferSize(flowId, newBufferSize);
    }
}
