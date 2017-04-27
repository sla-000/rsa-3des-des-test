package dial.sla000.ru.myapplication;

import org.junit.Assert;
import org.junit.Test;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

/**
 * Created by sla on 26/04/17.
 */

public class TestRSA {

	@Test
	public void encryptionRSA() throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance( "Blowfish" );
		keyGenerator.init( 128 );

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "RSA" );
		keyPairGenerator.initialize( 1024 );
		KeyPair keyPair = keyPairGenerator.genKeyPair();

		Cipher cipher = Cipher.getInstance( "RSA/ECB/PKCS1Padding" );
		cipher.init( Cipher.ENCRYPT_MODE, keyPair.getPublic() );

		byte[] blowfishKeyBytes = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B' };
		System.out.println( "blowfishKeyBytes: " + new String( blowfishKeyBytes ) + ", length: " + blowfishKeyBytes.length );
		byte[] cipherText = cipher.doFinal( blowfishKeyBytes );
		System.out.println( "cipherText: " + new String( cipherText ) + ", length: " + cipherText.length );
		cipher.init( Cipher.DECRYPT_MODE, keyPair.getPrivate() );

		byte[] decryptedKeyBytes = cipher.doFinal( cipherText );
		System.out.println( "decryptedKeyBytes: " + new String( decryptedKeyBytes ) + ", length: " + decryptedKeyBytes.length );

		Assert.assertArrayEquals( decryptedKeyBytes, blowfishKeyBytes );
	}

	@Test
	public void encryptionRSA_blowfish() throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance( "Blowfish" );
		keyGenerator.init( 128 );
		Key blowfishKey = keyGenerator.generateKey();

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "RSA" );
		keyPairGenerator.initialize( 1024 );
		KeyPair keyPair = keyPairGenerator.genKeyPair();

		Cipher cipher = Cipher.getInstance( "RSA/ECB/PKCS1Padding" );
		cipher.init( Cipher.ENCRYPT_MODE, keyPair.getPublic() );

		byte[] blowfishKeyBytes = blowfishKey.getEncoded();
		System.out.println( "blowfishKeyBytes: " + new String( blowfishKeyBytes ) + ", length: " + blowfishKeyBytes.length );
		byte[] cipherText = cipher.doFinal( blowfishKeyBytes );
		System.out.println( "cipherText: " + new String( cipherText ) + ", length: " + cipherText.length );
		cipher.init( Cipher.DECRYPT_MODE, keyPair.getPrivate() );

		byte[] decryptedKeyBytes = cipher.doFinal( cipherText );
		System.out.println( "decryptedKeyBytes: " + new String( decryptedKeyBytes ) + ", length: " + decryptedKeyBytes.length );

		Assert.assertArrayEquals( decryptedKeyBytes, blowfishKeyBytes );
	}
}
