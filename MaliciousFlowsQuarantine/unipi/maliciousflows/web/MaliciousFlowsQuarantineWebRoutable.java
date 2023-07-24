package net.floodlightcontroller.unipi.maliciousflows.web;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.core.web.ControllerSummaryResource;
import net.floodlightcontroller.core.web.ControllerSwitchesResource;
import net.floodlightcontroller.core.web.LoadedModuleLoaderResource;
import net.floodlightcontroller.restserver.RestletRoutable;

public class MaliciousFlowsQuarantineWebRoutable implements RestletRoutable {

    @Override
    public Restlet getRestlet(Context context) {
        Router router = new Router(context);

        // add some pre-defined REST resources available in the floodlight framework
        // summary stats of the controller
        router.attach("/controller/summary/json", ControllerSummaryResource.class);

        // show the list of module loaded in the controller
        router.attach("/module/loaded/json", LoadedModuleLoaderResource.class);

        // list the switches connected to the controller
        router.attach("/controller/switches/json", ControllerSwitchesResource.class);

        // custom resources
        router.attach("/flows/json", FlowsResource.class);
        router.attach("/quarantine/{id}/json", QuarantineBufferResource.class);

        return router;
    }

    @Override
    public String basePath() {
        return "/mfq";
    }
    
}
