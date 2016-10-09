import sun.misc.BASE64Decoder;
import java.io.BufferedReader;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * GenerateKeyUtil
 *
 * Created by sunfenglei on 16/10/8.
 */
public class GenerateKeyUtil {

    private static final String PUBLIC_KEY ="PUBLIC_KEY";
    private static final String PRIVATE_KEY ="PRIVATE_KEY";
    private static final String PUBLIC_KEY_FILE ="mercury_publickey.pem";
    private static final String PRIVATE_KEY_FILE ="mercury_privatekey.pem";

    private static BASE64Decoder mBase64decoder = new BASE64Decoder();
    private static Map<String, Object> mKeyMap = new HashMap<String, Object>();


    public static void initKey(){
        initPrivateKey();
        initPublicKey();
    }

    private static void initPrivateKey(){
        try {
            BufferedReader br = new BufferedReader(new FileReader(GenerateKeyUtil.class.getResource(PRIVATE_KEY_FILE).getPath()));
            String s = br.readLine();
            StringBuffer privateKeyBuffer = new StringBuffer();
            s = br.readLine();
            while (s.charAt(0) != '-') {
                privateKeyBuffer.append(s + "\r");
                s = br.readLine();
            }
            byte[] keyByte = mBase64decoder.decodeBuffer(privateKeyBuffer.toString());
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyByte);
            RSAPrivateKey privateKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
            mKeyMap.put(PRIVATE_KEY,privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private static void initPublicKey(){

        try {
            BufferedReader br = new BufferedReader(new FileReader(GenerateKeyUtil.class.getResource(PUBLIC_KEY_FILE).getPath()));
            String s = br.readLine();
            StringBuffer publicKeyBuffer = new StringBuffer();
            s = br.readLine();
            while (s.charAt(0) != '-') {
                publicKeyBuffer.append(s + "\r");
                s = br.readLine();
            }

            byte[] keyByte = mBase64decoder.decodeBuffer(publicKeyBuffer.toString());
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyByte);
            RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(keySpec);
            mKeyMap.put(PUBLIC_KEY,publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static RSAPrivateKey getPrivateKey(){
        return (RSAPrivateKey) mKeyMap.get(PRIVATE_KEY);
    }

    public static RSAPublicKey getPublicKey(){
        return (RSAPublicKey) mKeyMap.get(PUBLIC_KEY);
    }




}
