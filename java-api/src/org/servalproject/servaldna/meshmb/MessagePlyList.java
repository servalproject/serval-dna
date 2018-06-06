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

import org.servalproject.json.JsonObjectHelper;
import org.servalproject.json.JsonParser;
import org.servalproject.servaldna.HttpJsonSerialiser;
import org.servalproject.servaldna.HttpRequest;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SigningKey;

import java.io.IOException;

public class MessagePlyList extends HttpJsonSerialiser<PlyMessage, IOException> {
    private final SigningKey bundleId;
    private final String sinceToken;
    private String name;

    public MessagePlyList(ServalDHttpConnectionFactory httpConnector, SigningKey bundleId, String sinceToken){
        super(httpConnector);
        this.bundleId = bundleId;
        this.sinceToken = sinceToken;
        addField("offset", true, JsonObjectHelper.LongFactory);
        addField("token", true, JsonObjectHelper.StringFactory);
        addField("timestamp", false, JsonObjectHelper.LongFactory);
        addField("text", true, JsonObjectHelper.StringFactory);
    }

    public String getName(){
        return name;
    }

    @Override
    public void consumeObject(JsonParser.JsonMember header) throws IOException, JsonParser.JsonParseException {
        if (header.name.equals("name")){
            if (header.type == JsonParser.ValueType.Null)
                name = null;
            else if (header.type == JsonParser.ValueType.String)
                name = parser.readString();
            else
                parser.expected("value");
        }else
            super.consumeObject(header);
    }

    @Override
    protected HttpRequest getRequest() {
        String suffix;
        if (this.sinceToken == null)
            suffix = "/messagelist.json";
        else if(this.sinceToken.equals(""))
            suffix = "/newsince/messagelist.json";
        else
            suffix = "/newsince/" + sinceToken + "/messagelist.json";
        return new HttpRequest("GET", "/restful/meshmb/" + bundleId.toHex() + suffix);
    }

    @Override
    public PlyMessage create(Object[] parameters, int row) {
        return new PlyMessage(
                row,
                (Long)parameters[0],
                (String)parameters[1],
                (Long)parameters[2],
                (String)parameters[3]
        );
    }
}
