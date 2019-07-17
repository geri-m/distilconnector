package at.madlmayr;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;


public class DistilValve extends ValveBase {

    private static final Log log = LogFactory.getLog(DistilValve.class);

    // --------------------------------------------------------- Public Methods

    /**
     * Calling Distil as quick as possible to determine if the incoming call is a bot (or not)
     *
     * @param request  HTTP Request to the server
     * @param response HTTP Response from this Valve (might be modified)
     */

    @Override
    public void invoke(Request request, Response response) {
        long start = System.currentTimeMillis();
        log.info("Start " + start);
    }

}
