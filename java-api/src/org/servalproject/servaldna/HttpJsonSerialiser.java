/**
 * Copyright (C) 2016 Flinders University
 * Copyright (C) 2014-2015 Serval Project Inc.
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

import org.servalproject.json.JsonParser;
import org.servalproject.json.JsonTableSerialiser;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.List;

public abstract class HttpJsonSerialiser<T, E extends Exception> extends JsonTableSerialiser<T, E>{
    protected final ServalDHttpConnectionFactory httpConnector;
    protected HttpURLConnection httpConnection;
    protected boolean closed = false;
    protected InputStream inputStream;

    protected HttpJsonSerialiser(ServalDHttpConnectionFactory httpConnector){
        this.httpConnector = httpConnector;
    }

    protected abstract HttpRequest getRequest() throws UnsupportedEncodingException;

    public boolean isConnected(){
        return this.parser != null;
    }

    public void connect() throws IOException, ServalDInterfaceException{
        HttpRequest request = getRequest();
        boolean ret = request.connect(httpConnector);
        httpConnection = request.httpConnection;
        inputStream = request.inputStream;
        parser = request.parser;

        if (!ret)
            throw new ServalDUnexpectedHttpStatus(httpConnection);

        if (parser == null)
            throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + httpConnection.getContentType());

        try {
            begin(parser);
        } catch (JsonParser.JsonParseException e) {
            throw new ServalDInterfaceException(e);
        }
    }

    public void close() throws IOException
    {
        if (closed)
            return;
        closed = true;
        httpConnection = null;
        if (inputStream != null)
            inputStream.close();
    }

    @Deprecated
    public List<T> toList() throws ServalDInterfaceException, IOException, E {
        List<T> ret = new ArrayList<>();
        T item;
        try {
            while((item = next())!=null)
                ret.add(item);
        } catch (JsonParser.JsonParseException e) {
            throw new ServalDInterfaceException(e);
        }
        return ret;
    }
}
