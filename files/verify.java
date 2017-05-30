import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;



public class verify {

	// Raw data that is going to be signed
	private static final String rawData ="Hello SMART-ID";
	// Base64 encoded SHA512 hash of Raw data sent to SID service: snlTGncJvPNHOXknuOuxOhZDdrQMyW3FCixcyuMS2MSMAJrXAMwczp6O+1Ysn35FXQQylWBSaARVNjSwoD347w==

	// *** Signing ***
	private static final String sign_signature512Base64Encoded ="J3yF/+qdREitES13M/qFGHb1/1b4zbHaMcC24hnbzBWtHGLRWALHFh2O+S2idotRYEmKO93v/PG5ZGB5ojyyIdLpv+IxYEecWCBRJOfgmUD3Qq1L/zw+s0kwbEModFnUJWYbOcPGHcRB57PsFTcaVCQuN2Kc+/hxeg25lgzfTvwHIrDZDnjWKSs/NJBz8zrjO+yBblzJMS7eCraXfVoKB5j3q9USv0Hsj1KrQHrZIjOGAIXpVMxRtzznY6ZbdlGZmHIJitUMPNAPBQ+PHF24TuLI9C3wez2TXdUjnMxwHmgIVGjNpixxermyXhiLBsDQjZjQQG4OEKedKBBWNwd/Cco2Qf8AUsILD8sCc/5wPWWxdOWJN9AeeTmR114iWALTpFiOtI7saWt4lRIV1uAZHfFXvsAtXtN77IdKE7GRKRiQTavHX4d63aMzQN8BjEtRr4Lt/3Ex4DK2rn/fpEquUjr87GIzC029I5cyBu3A96fi7JIuSqWIYqw5e84R/fXmh054vWTC0iQ/0ZRsfGK17Z3HGJOdilyzliuc2JiQiR3h310bYHWna+cqfw6L6k9cbqKSPF/BYlzFKNKA2OSTRDdWFVbLmDlNerBsIjQOJ0aCXnt4gclcUvWkzuIO7vs53YlADVKDsTooOcyG7wwuWOFr5xSpuUbVEt5Gp27Ekvs=";
	private static final String sign_cert ="MIIHmTCCBYGgAwIBAgIQYoJV0riIvNVYkviOlmSJyjANBgkqhkiG9w0BAQsFADBnMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAMMElRFU1Qgb2YgTlEtU0sgMjAxNjAeFw0xNzAyMDIwOTE0NTRaFw0yMjAyMDEyMTU5NTlaMIG3MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEaMBgGA1UECwwRZGlnaXRhbCBzaWduYXR1cmUxKTAnBgNVBAMMIFNNQVJULUlELEhFTExPLFBOT0VFLTExNzAyMDIwMjAwMREwDwYDVQQEDAhTTUFSVC1JRDEOMAwGA1UEKgwFSEVMTE8xGjAYBgNVBAUTEVBOT0VFLTExNzAyMDIwMjAwMIICITANBgkqhkiG9w0BAQEFAAOCAg4AMIICCQKCAgB591fnrsce5bXAgg+0plUEyC1dSMz6/9lvZulE0NNrx2/7JLR34WXeeTWvu4HwhBEO9dNBBJEKga7nuzKrYepFQA4AAhY2Y2kmfXRg1bCTMVXyk1/zKpwxy+fuxsteJkHmTnoCt6zgofKJSCHSLpUKtdCWP4F9YAuZjw+jXM4ChOJeazNVZ8IxkIbJIq522MIGRakxA2XyIB37vVGnb1Z2plvmnjkE+hS1UrsPXJrUPuwrDhSHbsAwHX9HJmht9xFnhlj1xiJW6Sk1vQV8AFukX6iN4vkXEcNUZUoGWvYOnV9oOK+m2ysLzyuh9hK8a3IzRhxCCDMSyHn9oVv1apUF95FBekVg2a6pCS6ZzwiUkGfcmPhJPMlnrGWfmzebosZ47/1ZjUrRfQ4yyLODL/WIhSabw0dsl0VWOoYb2W6IrpfGZbqXZKC8A2vUZnqa3uUZX8I4iubbzj1YKXtQPhWdc6dnsadJ+nJHTVbGtYJMoP6Del4z+T5jdqpqO9ffa+mKhODbzZqak4I3ZJoJ9F3XaQKj8D+Pjveru9KIM7GIrO3QBbit6QULCR18taVptpgjXvyhYLi2wx5WKcjpy3cGTTygUhYGQSQU4JI/9vXCFxpre078XUF04fkzV1UYYRFrDZTHNGhqxcmzyzOrKmLhC8wDFH0ig5Q96KFNkT/WXQIDAQABo4IB7zCCAeswCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBkAwUgYDVR0gBEswSTA8BgorBgEEAc4fAxEBMC4wLAYIKwYBBQUHAgEWIGh0dHBzOi8vc2suZWUvZW4vcmVwb3NpdG9yeS9DUFMvMAkGBwQAi+xAAQEwHQYDVR0OBBYEFOMo7rcCx10GgJ/pJcMDttEqm9RZMIGOBggrBgEFBQcBAwSBgTB/MBMGBgQAjkYBBjAJBgcEAI5GAQYBMFEGBgQAjkYBBTBHMEUWP2h0dHBzOi8vc2suZWUvZW4vcmVwb3NpdG9yeS9jb25kaXRpb25zLWZvci11c2Utb2YtY2VydGlmaWNhdGVzLxMCRU4wFQYIKwYBBQUHCwIwCQYHBACL7EkBATAfBgNVHSMEGDAWgBSsw050xt/OPR3E74FhBbZv3UkdPTB2BggrBgEFBQcBAQRqMGgwIwYIKwYBBQUHMAGGF2h0dHA6Ly9haWEuc2suZWUvbnEyMDE2MEEGCCsGAQUFBzAChjVodHRwczovL3NrLmVlL3VwbG9hZC9maWxlcy9URVNUX29mX05RLVNLXzIwMTYuZGVyLmNydDAxBgNVHREEKjAopCYwJDEiMCAGA1UEAwwZUE5PRUUtMTE3MDIwMjAyMDAtMDVOWC1OUTANBgkqhkiG9w0BAQsFAAOCAgEAIZSTb23/8Wxf39qroYRIKhKY7OjAJVdZxOObTGjhxaIDZcwE7HUdWTuDF2MUrbHqgMEGk7EE0pdHG/+fUu8ozvo+Rj0GjODHzA5dsxuv7PU2yUp888RHYe0Nqp2MCL+YnqqPW5mAlAF38LPGHNWM8zSKOkHLyoOZQo1WZTsj57bgPO2+b9+5VkF733ygcxWCPao514iS6LnkwsG/Xq2Wm8LF5pLkgpAio2384QjN1zjrneVjBI7sCyCIUZ7dlkHFZHalikqn0ZeJ+q5vKodgG40/1OhYR5ypMsBCVMC4FrxuJYuPUsTqqKR35B8bSx2leu+GLAOEq0Wn8Ox++7B07iz19iOspq1hDgxFbAFNL17Uvcqlf1j+vI9SA57nc3RK06ZRDIxXkoKWgE00Oo1TGt1bPqrwAsLgddVbMR2XISX4qnIGDWSgDWWyVa3gHK2p2Tb337SUy3FDaku5mRZuEMxv8npyxNsD95ZVo4DiD+XEu/rsaF8D+QSY8jlMyf1rqfIL/LHuI2XH2rIlXMdL1f4P3z+096uN1AEEWJ6Zpt3LwPvn38lMfE6PUU6nTYpK19vmCdZhDs+b/IkCpgsPJxdh8RicIqf+w6V92lF22mD24y0NVBvuhL5wKI70Kgp4i/iCMKbmm23P37ivCCcrUf+IxUyYJ4hlOOXN6tfaf8A=";
	
	// *** Authentication ***
	// Authentication signature returned by SID service
	private static final String auth_signature512Base64Encoded ="Ooa9Jf4Wg+SrxaXbxFavk8gL6Bo/DIggk4NUxxzzzR5piVD6fNgNdo2bYXh3gWB9I9veyf3uqGotefvOlR8X7ndPJoyqfUIdftx5GI301XLqJnIYEERFlwRDyEwIVOH149B9feLVEEzr+ArXWa12TyelxvcYv2TgLUjgokFk8j8aimdA4jY+HR/nirvQO7gy8MkzjMoagvxOSAKoRFaOPUP5KT2qIPDC2wwHwShRctdQlWsAyto1G5Pdm82FHK3OYOLQPBNuhz8+CT2iKxZY/Uqi6Xr+Mc1JKHK/IPo9MYUFDW+FvKFixF9efnDuRhOTSpj6scvvr00EQoBCAyZpPzlfd/aQddcVnyGvNxDQ02OkksmdWLgzsYGwBLyJnAjGN1MOl++mXf508/ctkWHgyrJUP8r6PWOMriz1gP8VJPe6h7e0cmvexgoZmLFV9Xev23iNyJ7VG0ovhjC2Bw84qQ6by3WebJzadmFznPbeLdxpwCJVw/aoc2pyASDATjAVWimUt2fJD4VY8f3XQz0bBIUG4TbPwbX7wyDewQOXgU0UAPqKGh/2130f3Y7eV3Sjv2xFxk4ih4RIMoruEQfOK/b92UGg6RsS9+ctHH1LftLZO3HdF8sfDQhvWDPvbzmFa2gD3RaKR6QguGfauxbtE78ARZiAnrtkcHHOjYc/p0k=";
	// Certificate returned by SID service
	private static final String auth_cert ="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";


	public static void main(final String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException, InvalidKeyException, SignatureException {
		final X509Certificate sign_userCert = getCertificateFromString(sign_cert);
		final X509Certificate auth_userCert = getCertificateFromString(auth_cert);
		
		PublicKey sign_pk = sign_userCert.getPublicKey();
		PublicKey auth_pk = auth_userCert.getPublicKey();

		//Base64 encoded SHA512 hash of Raw data sent to SID service
		final String rawDataSHA512Base64Encoded=get_SHA512(rawData.getBytes());
		System.out.println("hash sent to service: "+ rawDataSHA512Base64Encoded);

		// Verification code
		System.out.println("Verification code: " + getVerificationCode(rawDataSHA512Base64Encoded));
		System.out.print("Verifying Signing signature: ");
		verifySignature(sign_pk, sign_signature512Base64Encoded, rawData.getBytes());
		System.out.print("Verifying Authentication signature: ");
		verifySignature(auth_pk, auth_signature512Base64Encoded, rawData.getBytes());
	}


	public static void verifySignature(final PublicKey publicKey, final String signatureBase64, final byte[] rawSignedData) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		final byte[] signature = Base64.getDecoder().decode(signatureBase64);

		final Signature verifier = Signature.getInstance("SHA512withRSA");
		verifier.initVerify(publicKey);
		verifier.update(rawSignedData);

		if (verifier.verify(signature)){
			System.out.println("successful");
		}
		else{
			System.out.println("failed");
		}

	}

	public static X509Certificate getCertificateFromString(final String cert) {
		final byte [] decoded = Base64.getDecoder().decode(cert);

		try {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
		} catch (final CertificateException e) {
			e.printStackTrace();
			return null;
		}
	}


	public static String getVerificationCode(final String rawHashInBase64) {
		MessageDigest sha256;

		try {
			sha256 = MessageDigest.getInstance("SHA-256");
		} catch (final NoSuchAlgorithmException e) {
			throw new IllegalStateException("No SHA-256?", e);
		}

		// Hash raw input with SHA256
		final ByteBuffer sha256HashedInput = ByteBuffer.wrap(
				sha256.digest(Base64.getDecoder().decode(rawHashInBase64)));

		// extract 2 rightmost bytes from it, interpret them as a big-endian unsigned integer and take the last 4 digits in decimal
		final String code = String.valueOf(
				((int) sha256HashedInput.getShort(sha256HashedInput.limit() - Short.BYTES)) & 0xffff);

		// .. and pad with zeroes.
		return ("0000" + code).substring(code.length());
	}
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(final byte[] bytes) {
		final char[] hexChars = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ ) {
			final int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}


	public static String get_SHA512(final byte[] DataToHash){
		String generatedHash = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("SHA-512");
			final byte[] bytes = md.digest(DataToHash);        	         
			generatedHash = Base64.getEncoder().encodeToString(bytes);
		} 
		catch (final NoSuchAlgorithmException e){
			e.printStackTrace();
		}
		return generatedHash;
	}
}
