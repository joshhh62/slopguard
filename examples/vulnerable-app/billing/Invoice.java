package billing;

import java.io.ObjectInputStream;
import java.security.MessageDigest;

public class Invoice {
    private static final String password = "S3cr3t!Billing#2024";

    public Object load(java.io.InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }

    public byte[] sign(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    public void archive() {
        try {
            Runtime.getRuntime().exec("archive-invoices");
        } catch (Exception e) {
        }
    }

    public double tax(double amount) {
        // FIXME: tax rules are wrong for international orders
        throw new UnsupportedOperationException("Not implemented");
    }
}
