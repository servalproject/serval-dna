package org.servalproject.servaldna;

import org.servalproject.servaldna.rhizome.RhizomeIncompleteManifest;
import org.servalproject.servaldna.rhizome.RhizomeManifest;
import org.servalproject.servaldna.rhizome.RhizomeManifestSizeException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;

/**
 * Created by jeremy on 5/10/16.
 */
public class PostHelper {
    private HttpURLConnection conn;
    private String boundary;
    private OutputStream output;
    private PrintStream writer;

    public PostHelper(HttpURLConnection conn) {
        this.conn = conn;
        boundary = Long.toHexString(System.currentTimeMillis());
    }

    public void connect() throws IOException {
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
        conn.setRequestProperty("Expect", "100-continue");
        conn.setChunkedStreamingMode(0);
        conn.connect();
        output = conn.getOutputStream();
        writer = new PrintStream(output, false, "UTF-8");
    }

    private void quoteString(StringBuilder sb, String unquoted)
    {
        if (unquoted == null) {
            sb.append("null");
            return;
        }
        sb.append('"');
        for (int i = 0; i < unquoted.length(); ++i) {
            char c = unquoted.charAt(i);
            if (c == '"' || c == '\\')
                sb.append('\\');
            sb.append(c);
        }
        sb.append('"');
    }

    public void writeHeading(String name, String filename, String type, String encoding)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("\r\n--").append(boundary).append("\r\n");
        sb.append("Content-Disposition: form-data; name=");
        quoteString(sb, name);
        if (filename!=null) {
            sb.append("; filename=");
            quoteString(sb, filename);
        }
        sb.append("\r\n");
        sb.append("Content-Type: ").append(type).append("\r\n");
        if (encoding!=null)
            sb.append("Content-Transfer-Encoding: ").append(encoding).append("\r\n");
        sb.append("\r\n");
        writer.print(sb.toString());
    }

    public void writeField(String name, String value){
        writeHeading(name, null, "text/plain; charset=utf-8", null);
        writer.print(value);
    }

    public void writeField(String name, AbstractId value){
        writeHeading(name, null, value.getMimeType(), "hex");
        writer.print(value.toHex());
    }

    public void writeField(String name, String filename, InputStream stream) throws IOException {
        writeHeading(name, filename, "application/octet-stream", "binary");
        writer.flush();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = stream.read(buffer)) > 0)
            output.write(buffer, 0, n);
    }

    public void writeField(String name, RhizomeManifest manifest) throws IOException, RhizomeManifestSizeException {
        writeHeading(name, null, "rhizome/manifest; format=\"text+binarysig\"", "binary");
        manifest.toTextFormat(writer);
    }

    public void writeField(String name, RhizomeIncompleteManifest manifest) throws IOException {
        writeHeading(name, null, "rhizome/manifest; format=\"text+binarysig\"", "binary");
        manifest.toTextFormat(writer);
    }

    public void close(){
        if (writer==null)
            return;
        writer.print("\r\n--" + boundary + "--\r\n");
        writer.flush();
        writer.close();
    }
}
