package dial.sla000.ru.myapplication;

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * DES and 3DES test
 */
public class TestDES {
	private interface CONST {
		byte[] plainTextBytes = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		byte[] keyBytes1 = { (byte)0x00, (byte)0x7E, (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE };
		byte[] keyBytes2 = { (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0x7E, (byte)0x00 };

		byte[] result = { (byte)0xe7, (byte)0x3a, (byte)0xfe, (byte)0x45, (byte)0x07, (byte)0x57, (byte)0x54, (byte)0x0b };
	}

	/**
	 * 3des-ede step by step with des
	 *
	 * Same as:
	 * <p>
	 * openssl enc -e -des -in in.bin -out out1.bin -K 007EFEFEFEFEFEFE -iv 0000000000000000 -nopad
	 * openssl enc -d -des -in out1.bin -out out2.bin -K FEFEFEFEFEFE7E00 -iv 0000000000000000 -nopad
	 * openssl enc -e -des -in out2.bin -out out3.bin -K 007EFEFEFEFEFEFE -iv 0000000000000000 -nopad
	 * <p>
	 * or
	 * <p>
	 * openssl enc -e -des-ede3-cbc -in in.bin -out out.bin -K 007EFEFEFEFEFEFEFEFEFEFEFEFE7E00007EFEFEFEFEFEFE -iv 0000000000000000 -nopad
	 *
	 * sla@osboxes ~ $ hexdump -C out.bin
	 * 00000000  e7 3a fe 45 07 57 54 0b                           |.:.E.WT.|
	 *
	 * @throws Exception
	 */
	@Test
	public void encryption3TimesDES() throws Exception {
		final byte[] stage1;
		final byte[] stage2;
		final byte[] stage3;

		final Cipher desCipher = Cipher.getInstance( "DES/ECB/NoPadding" );

		final SecretKey keySpec1 = new SecretKeySpec( CONST.keyBytes1, "DES" );
		final SecretKey keySpec2 = new SecretKeySpec( CONST.keyBytes2, "DES" );

		{
			desCipher.init( Cipher.ENCRYPT_MODE, keySpec1 );

			stage1 = desCipher.doFinal( CONST.plainTextBytes );

			{
				for( int q = 0; q < stage1.length; ++q ) {
					System.out.format( "0x%02X, ", stage1[q] );
				}
				System.out.format( "\n" );
			}
		}

		{
			desCipher.init( Cipher.DECRYPT_MODE, keySpec2 );

			stage2 = desCipher.doFinal( stage1 );

			{
				for( int q = 0; q < stage2.length; ++q ) {
					System.out.format( "0x%02X, ", stage2[q] );
				}
				System.out.format( "\n" );
			}
		}

		{
			desCipher.init( Cipher.ENCRYPT_MODE, keySpec1 );

			stage3 = desCipher.doFinal( stage2 );

			{
				for( int q = 0; q < stage3.length; ++q ) {
					System.out.format( "0x%02X, ", stage3[q] );
				}
				System.out.format( "\n" );
			}
		}

		Assert.assertArrayEquals( stage3, CONST.result );
	}

	/**
	 * 3des-ede by one call of Cipher
	 *
	 * @throws Exception
	 */
	@Test
	public void encryption3DES_ecb() throws Exception {
		final byte[] keyBytes = new byte[24];

		System.arraycopy( CONST.keyBytes1, 0, keyBytes, 0, 8 );
		System.arraycopy( CONST.keyBytes2, 0, keyBytes, 8, 8 );
		System.arraycopy( CONST.keyBytes1, 0, keyBytes, 16, 8 );

		{
			final SecretKey key = new SecretKeySpec( keyBytes, "DESede" );
			final Cipher cipher = Cipher.getInstance( "DESede/ECB/NoPadding" );
			cipher.init( Cipher.ENCRYPT_MODE, key );

			{
				final byte[] cipherText = cipher.doFinal( CONST.plainTextBytes );
				for( int q = 0; q < cipherText.length; ++q ) {
					System.out.format( "0x%02X, ", cipherText[q] & 0xFF );
				}

				System.out.format( "\n" );

				Assert.assertArrayEquals( cipherText, CONST.result );
			}
		}
	}
}