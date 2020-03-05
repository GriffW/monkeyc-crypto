using Toybox.Cryptography   as Cryptography;
using Toybox.StringUtil     as StrUtl;

module Crypto
{
    const BLOCK_SIZE_BYTES      = 32;
    const IV_SIZE_BYTES         = 16;
    const KDF_SALT_SIZE_BITS    = 128;

    // desc: adds padding to AES
    // inputs:
    // - plain_text_in  [string]    text to have padding added
    // returns:
    // - [str] padded text
    function AESPadData( plain_text_in )
    {
        var data        = plain_text_in.toCharArray();
        var data_size   = data.size();
        var padding     = BLOCK_SIZE_BYTES - ( data_size % BLOCK_SIZE_BYTES );

        if( padding == 0 )
        {
            padding = BLOCK_SIZE_BYTES;
        }

        for( var i = 0; i < padding; ++i )
        {
            data.add( padding );
        }

        return data;
    }

    // desc: encrypts plain text
    // inputs:
    // - text_in    [str]   string to encrypt
    // - key_in     [bytes] key to encrypt data with
    // returns:
    // - [bytes]    encrypted cypher text
    function encrypt( text_in, key_in )
    {
        var text_to_encrypt = AESPadData( text_in );
        var generated_iv    = Cryptography.randomBytes( IV_SIZE_BYTES );

        var aes_256_cipher = new Cryptography.Cipher(
            {
                :algorithm    => Cryptography.CIPHER_AES256,
                :mode         => Cryptography.MODE_CBC,
                :key          => key_in,
                :iv           => generated_iv
            });

        var encrypted_data = aes_256_cipher.encrypt( []b.addAll( text_to_encrypt ) );

        return generated_iv.addAll( encrypted_data );
    }

    // desc: decrypts plain text
    // inputs:
    // - encrypted_data_in  [bytes] string to decrypt
    // - key_in             [bytes] key to encrypt data with
    // returns:
    // - [bytes]    decrypted cypher text
    function decrypt( encrypted_data_in, key_in )
    {
        //get iv
        var data_iv         = encrypted_data_in.slice( 0, IV_SIZE_BYTES );
        var encrypted_data  = encrypted_data_in.slice( IV_SIZE_BYTES, encrypted_data_in.size() );

        var aes_256_cipher = new Cryptography.Cipher(
            {
                :algorithm    => Cryptography.CIPHER_AES256,
                :mode         => Cryptography.MODE_CBC,
                :key          => key_in,
                :iv           => data_iv
            } );

        var decrypted_data = aes_256_cipher.decrypt( encrypted_data );
        var padding_length = decrypted_data[decrypted_data.size() - 1];

        return decrypted_data.slice( 0, -padding_length );
    }

    function kdf( password_in )
    {
        var kdf_salt = Cryptography.randomBytes( KDF_SALT_SIZE_BITS / 8 );
        var sha_256 = new Cryptography.Hash(
            {
                :algorithm => Cryptography.HASH_SHA256
            } );

        var password_bytes = StrUtl.convertEncodedString( password_in,
            {
                :fromRepresentation => StrUtl.REPRESENTATION_STRING_PLAIN_TEXT,
                :toRepresentation   => StrUtl.REPRESENTATION_BYTE_ARRAY,
            } );
        var input = password_bytes.addAll( kdf_salt );
        sha_256.update( input );
        var key = sha_256.digest();

        return [kdf_salt, key];
    }
}