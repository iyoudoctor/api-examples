import com.auth0.jwt.Algorithm;
import com.auth0.jwt.JWTSigner;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTVerifyException;
import sun.misc.BASE64Decoder;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * The api sign example.
 *
 * Created by sunfenglei on 16/10/8.
 */
public class Sign {

    private static BASE64Decoder mBase64decoder = new BASE64Decoder();

    public static void main(String[] args) {
        initParams(args);
    }


    private static void initParams(String[] args){
        System.out.println("Please input params:");
        Scanner input = new Scanner(System.in);
        System.out.print("Please input action type(sign/verify):");
        String action = input.next();
        while(!action.trim().equals("sign") && !action.trim().equals("verify")){
            System.out.print("Please input action type(sign/verify):");
            action = input.next();
        }
        System.out.print("Please input appId:");
        String appId = input.next();
        System.out.print("Please input UTC timestamp(input 0 use default current time):");
        long time = Long.parseLong(input.next());
        System.out.print("Please input path:");
        String path = input.next();
        System.out.print("Please input key path:");
        String keyPath = input.next();


        if(action.equals("sign".trim())){
            input.close();
            long utcTime=getUTC();
            if(time>0){
                utcTime = time;
            }
            signHttp(appId,path,utcTime,generatePrivateKey(keyPath));
        }else if(action.equals("verify".trim())){
            System.out.print("Please input signature:");
            String signature = input.next();
            input.close();
            try {
                verifyHttp(appId,path, time,signature,generatePublicKey(keyPath));
            } catch (SignatureException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (JWTVerifyException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }else{
            System.out.print("Invalid action type!!!");
        }
    }




    /**
     * Sign http
     *
     * @param appID
     *
     * @param path
     *
     * @param utcTime
     *
     * @param privateKey
     */

    public static void signHttp(String appID,String path,long utcTime,RSAPrivateKey privateKey)  {
        final JWTSigner signer = new JWTSigner(privateKey);
        final HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("appID", appID);
        claims.put("path", path);
        claims.put("utctime", parseRFC3339Date(utcTime));
        JWTSigner.Options options = new JWTSigner.Options();
        options.setAlgorithm(Algorithm.RS256);
        String signature = signer.sign(claims,options);
        System.out.println("signature : "+signature);
    }

    /**
     * Verify http
     *
     * @param appID
     *
     * @param path
     *
     * @param utcTime
     *
     * @param signature
     *
     * @param publicKey
     */
    public static boolean verifyHttp(String appID,String path,long utcTime,String signature,RSAPublicKey publicKey) throws SignatureException, NoSuchAlgorithmException, JWTVerifyException, InvalidKeyException, IOException{
        final JWTVerifier verifier = new JWTVerifier(publicKey);
        final Map<String, Object> claims = verifier.verify(signature);
        System.out.println("appID : "+claims.get("appID"));
        System.out.println("path : "+claims.get("path"));
        System.out.println("utcTime : "+claims.get("utctime"));
        if(claims.get("appID").equals(appID) && claims.get("path").equals(path) && claims.get("utctime").equals(parseRFC3339Date(utcTime))){
            System.out.println("Validation passed!");
            return true;
        }else{
            System.out.println("Validation failed!");
            return false;
        }

    }

     /**
     * Generate Public Key.
     *
     * @param path
     *            The public key path.
     *
     * @return RSAPublicKey
     */
    private static RSAPublicKey generatePublicKey(String path){

        try {
            BufferedReader br = new BufferedReader(new FileReader(path));
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
            return publicKey;
        } catch (Exception e) {
            e.printStackTrace();

        }
        return null;
    }

    /**
     * Generate Private Key.
     *
     * @param path
     *            The private key path.
     *
     * @return RSAPrivateKey
     */
    private static RSAPrivateKey generatePrivateKey(String path){
        try {
            BufferedReader br = new BufferedReader(new FileReader(path));
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
            return privateKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }



    /**
     * Generate UTC time.
     *
     * @return the current time as UTC milliseconds
     */
    private static long getUTC(){
        // 1、取得本地时间：
        Calendar cal = Calendar.getInstance() ;
        // 2、取得时间偏移量：
        int zoneOffset = cal.get(java.util.Calendar.ZONE_OFFSET);
        // 3、取得夏令时差：
        int dstOffset = cal.get(java.util.Calendar.DST_OFFSET);
        // 4、从本地时间里扣除这些差量，即可以取得UTC时间：
        cal.add(java.util.Calendar.MILLISECOND, -(zoneOffset + dstOffset));
        return cal.getTimeInMillis();
    }



    public static String parseRFC3339Date(long timestamp) {
        Date d = new Date(timestamp);
        SimpleDateFormat format = new SimpleDateFormat(
                "yyyy-MM-dd'T'HH:mm:ss'Z'");// spec for RFC3339
        String rfcTime = format.format(d);
        return rfcTime;
    }



}
