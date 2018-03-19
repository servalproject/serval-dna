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

package org.servalproject.servaldna.meshmb;

import org.servalproject.json.JSONInputException;
import org.servalproject.json.JSONTableScanner;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.servaldna.AbstractJsonList;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SigningKey;

import java.io.IOException;
import java.util.Map;

public class MessagePlyList extends AbstractJsonList<PlyMessage, IOException> {
    private final SigningKey bundleId;
    private final String sinceToken;
    private String name;

    public MessagePlyList(ServalDHttpConnectionFactory httpConnector, SigningKey bundleId, String sinceToken){
        super(httpConnector, new JSONTableScanner()
                .addColumn("offset", Long.class)
                .addColumn("token", String.class)
                .addColumn("text", String.class)
                .addColumn("timestamp", Long.class, JSONTokeniser.Narrow.ALLOW_NULL));
        this.bundleId = bundleId;
        this.sinceToken = sinceToken;
    }

    public String getName(){
        return name;
    }

    @Override
    protected void consumeHeader() throws JSONInputException, IOException {
        Object tok = json.nextToken();
        if (tok.equals("name")) {
            json.consume(JSONTokeniser.Token.COLON);
            name = json.consume(String.class);
            json.consume(JSONTokeniser.Token.COMMA);
        }
    }

    @Override
    protected void handleResponseError() throws IOException, ServalDInterfaceException {
        // TODO handle specific errors
        super.handleResponseError();
    }

    @Override
    protected Request getRequest() {
        if (this.sinceToken == null)
            return new Request("GET", "/restful/meshmb/" + bundleId.toHex() + "/messagelist.json");
        else if(this.sinceToken.equals(""))
            return new Request("GET", "/restful/meshmb/" + bundleId.toHex() + "/newsince/messagelist.json");
        else
            return new Request("GET", "/restful/meshmb/" + bundleId.toHex() + "/newsince/" + sinceToken + "/messagelist.json");
    }

    @Override
    protected PlyMessage factory(Map<String, Object> row, long rowCount) {
        return new PlyMessage(
                rowCount,
                (Long)row.get("offset"),
                (String)row.get("token"),
                (Long)row.get("timestamp"),
                (String)row.get("text")
        );
    }
}
