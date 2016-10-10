package org.servalproject.servaldna;

import org.servalproject.json.JSONInputException;
import org.servalproject.json.JSONTableScanner;
import org.servalproject.json.JSONTokeniser;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created by jeremy on 10/10/16.
 */
public abstract class AbstractJsonList<T, E extends Exception> {
    protected final ServalDHttpConnectionFactory httpConnector;
    protected final JSONTableScanner table;
    protected HttpURLConnection httpConnection;
    protected JSONTokeniser json;
    protected long rowCount = 0;

    protected AbstractJsonList(ServalDHttpConnectionFactory httpConnector, JSONTableScanner table){
        this.httpConnector = httpConnector;
        this.table = table;
    }

    protected abstract String getUrl();

    public boolean isConnected(){
        return this.json != null;
    }

    protected void consumeHeader() throws JSONInputException, IOException {
        throw new JSONTokeniser.UnexpectedTokenException(json.nextToken());
    }

    protected void handleResponseError() throws E, IOException, ServalDInterfaceException {
        throw new ServalDFailureException("received unexpected HTTP Status "+
                httpConnection.getResponseCode()+" " + httpConnection.getResponseMessage()+" from " + httpConnection.getURL());
    }

    public void connect() throws IOException, ServalDInterfaceException, E {
        String url = getUrl();
        httpConnection = httpConnector.newServalDHttpConnection(url);
        httpConnection.connect();

        if (!httpConnection.getContentType().equals("application/json"))
            throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + httpConnection.getContentType());

        json = new JSONTokeniser(
                (httpConnection.getResponseCode() >= 300) ?
                        httpConnection.getErrorStream() : httpConnection.getInputStream());

        if (httpConnection.getResponseCode()!=200){
            handleResponseError();
            return;
        }

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
        httpConnection = null;
        if (json != null) {
            json.close();
            json = null;
        }
    }
}
