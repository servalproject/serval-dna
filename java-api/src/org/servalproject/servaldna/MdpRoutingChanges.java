/**
 * Copyright (C) 2016 Flinders University
 *
 * This file is part of Serval Software (http://www.servalproject.org)
 *
 * Serval Software is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this source code; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package org.servalproject.servaldna;

import java.io.IOException;
import java.nio.BufferUnderflowException;

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
