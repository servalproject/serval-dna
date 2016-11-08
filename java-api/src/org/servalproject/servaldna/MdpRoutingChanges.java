package org.servalproject.servaldna;

import java.io.IOException;
import java.nio.BufferUnderflowException;

/**
 * Created by jeremy on 10/05/16.
 */
public class MdpRoutingChanges extends AbstractMdpProtocol<RouteLink>{

    private static final int MDP_ROUTE_TABLE = 5;

    public MdpRoutingChanges(ChannelSelector selector, int loopbackMdpPort, AsyncResult<RouteLink> results) throws IOException {
        super(selector, loopbackMdpPort, results, SubscriberId.Internal, MDP_ROUTE_TABLE);
        refresh();
    }

    public void refresh() throws IOException {
        MdpPacket request = new MdpPacket();
        request.setRemoteSid(SubscriberId.ANY);
        request.setRemotePort(MDP_ROUTE_TABLE);
        request.payload.flip();
        socket.send(request);
    }

    @Override
    protected void parse(MdpPacket response) {
        try {
            while(response.payload.hasRemaining())
                results.result(new RouteLink(response.payload));
        } catch (AbstractId.InvalidBinaryException e) {
            e.printStackTrace();
        } catch (BufferUnderflowException e){
            e.printStackTrace();
        }
    }
}
