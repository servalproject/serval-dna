package org.servalproject.servaldna.meshmb;

/**
 * Created by jeremy on 10/10/16.
 */
public class PlyMessage {

    public final long _row;
    public final long offset;
    public final String token;
    public final long timestamp;
    public final String text;
    public PlyMessage(long _row, long offset, String token, long timestamp, String text){
        this._row = _row;
        this.offset = offset;
        this.token = token;
        this.timestamp = timestamp;
        this.text = text;
    }
}
