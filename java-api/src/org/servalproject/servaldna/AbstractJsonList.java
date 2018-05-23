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

import org.servalproject.json.JSONInputException;
import org.servalproject.json.JSONTableScanner;
import org.servalproject.json.JSONTokeniser;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public abstract class AbstractJsonList<T, E extends Exception> {
    protected final ServalDHttpConnectionFactory httpConnector;
    protected final JSONTableScanner table;
    protected HttpURLConnection httpConnection;
    protected JSONTokeniser json;
    protected boolean closed = false;
    protected long rowCount = 0;

	protected class Request {
		String verb;
		String url;

		public Request(String verb, String url) {
			this.verb = verb;
			this.url = url;
		}
	}

    protected AbstractJsonList(ServalDHttpConnectionFactory httpConnector, JSONTableScanner table){
        this.httpConnector = httpConnector;
        this.table = table;
    }

    protected abstract Request getRequest();

    public boolean isConnected(){
        return this.json != null;
    }

    protected void consumeHeader() throws JSONInputException, IOException {
        throw new JSONTokeniser.UnexpectedTokenException(json.nextToken());
    }

    protected void handleResponseError() throws E, IOException, ServalDInterfaceException {
        throw new ServalDUnexpectedHttpStatus(httpConnection);
    }

    public void connect() throws IOException, ServalDInterfaceException, E {
		Request request = getRequest();
        httpConnection = httpConnector.newServalDHttpConnection(request.verb, request.url);
        httpConnection.connect();

        try {
            ContentType contentType = new ContentType(httpConnection.getContentType());
            if (ContentType.applicationJson.matches(contentType)){
                json = new JSONTokeniser(
                        (httpConnection.getResponseCode() >= 300) ?
                                httpConnection.getErrorStream() : httpConnection.getInputStream());
            }
        } catch (ContentType.ContentTypeException e) {
            throw new ServalDInterfaceException("malformed HTTP Content-Type: " + httpConnection.getContentType(), e);
        }

        if (httpConnection.getResponseCode()!=200){
            handleResponseError();
            return;
        }

        if (json == null)
            throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + httpConnection.getContentType());

        try{
            json.consume(JSONTokeniser.Token.START_OBJECT);
            // allow for extra optional fields
            while(true) {
                Object tok = json.nextToken();
                if (tok.equals("header"))
                    break;
                json.pushToken(tok);
                consumeHeader();
            }
            json.consume(JSONTokeniser.Token.COLON);
            table.consumeHeaderArray(json);
            json.consume(JSONTokeniser.Token.COMMA);
            json.consume("rows");
            json.consume(JSONTokeniser.Token.COLON);
            json.consume(JSONTokeniser.Token.START_ARRAY);
        }catch (JSONInputException e){
            throw new ServalDInterfaceException(e);
        }
    }

    protected abstract T factory(Map<String,Object> row, long rowCount) throws ServalDInterfaceException;

    public T next() throws ServalDInterfaceException, IOException{
        try {
            Object tok = json.nextToken();
            if (tok == JSONTokeniser.Token.END_ARRAY) {
                json.consume(JSONTokeniser.Token.END_OBJECT);
                json.consume(JSONTokeniser.Token.EOF);
                return null;
            }
            if (closed && tok == JSONTokeniser.Token.EOF)
                return null;
            if (rowCount != 0)
                JSONTokeniser.match(tok, JSONTokeniser.Token.COMMA);
            else
                json.pushToken(tok);
            Map<String,Object> row = table.consumeRowArray(json);
            return factory(row, rowCount++);
        } catch (JSONInputException e) {
            throw new ServalDInterfaceException(e);
        }
    }

    public List<T> toList() throws ServalDInterfaceException, IOException {
        List<T> ret = new ArrayList<T>();
        T item;
        while ((item = next()) != null) {
            ret.add(item);
        }
        return ret;
    }

    public void close() throws IOException
    {
        if (closed)
            return;
        closed = true;
        httpConnection = null;
        if (json != null)
            json.close();
    }
}
