package contracts.Utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class Util {
    public static final String formatRFC3339UTC = "yyyy-MM-dd'T'HH:mm:ss";

    public static SimpleDateFormat getDateFormatRFC3339UTC() {
        SimpleDateFormat dateFormatRFC3339UTC = new SimpleDateFormat(formatRFC3339UTC);
        dateFormatRFC3339UTC.setTimeZone(TimeZone.getTimeZone("UTC"));
        return dateFormatRFC3339UTC;
    }

    public static String toRFC3339UTC(Date date) {
        return getDateFormatRFC3339UTC().format(date);
    }

    public static Date fromRFC3339UTC(String str) {
        try {
            return getDateFormatRFC3339UTC().parse(str);
        }
        catch (ParseException e) {
            return null;
        }
    }

}
