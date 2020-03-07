using Toybox.Cryptography   as Cryptography;
using Toybox.StringUtil     as StrUtl;
using Toybox.System as Sys;

module Crypto
{
    enum
    {
        KDF_RET_KEY,
        KDF_RET_SALT,
        KDF_RET_SIZE
    }

    const BLOCK_SIZE_BYTES      = 32;
    const IV_SIZE_BYTES         = 16;
    const KDF_SALT_SIZE_BYTES   = 16;

    const PBKDF2_HMAC_ITERATIONS = 150;

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

    // desc: generates a cryptographically secure key from a passphrase
    // inputs:
    // - password_in  [string]  string to turn into a key
    // returns:
    // - [[bytes], [bytes]]    generated key and salt required to generate it
    function kdf( password_in )
    {
        return pbkdf2_hmac( password_in, PBKDF2_HMAC_ITERATIONS );
    }

    // TODO support outputs larger than 256b
    private function pbkdf2_hmac( password_in, iterations )
    {
        var password_bytes = StrUtl.convertEncodedString( password_in,
            {
                :fromRepresentation => StrUtl.REPRESENTATION_STRING_PLAIN_TEXT,
                :toRepresentation   => StrUtl.REPRESENTATION_BYTE_ARRAY,
            } );

        // generate first iteration
        var sha_256 = new Cryptography.HashBasedMessageAuthenticationCode(
            {
                :algorithm  => Cryptography.HASH_SHA256,
                :key        => password_bytes
            } );

        var kdf_salt = Cryptography.randomBytes( KDF_SALT_SIZE_BYTES );
        sha_256.update( kdf_salt );

        // concatenation of salt and block number
        var int_32b = [0, 0, 0, 1]b;
        sha_256.update( int_32b );

        var t = sha_256.digest();
        var u = []b.addAll( t );

        // iterations starting at 1 because of the initial setup
        for( var i = 1; i < iterations; ++i )
        {
            // hash the hash then xor it with the previous hash
            sha_256.update( u );
            u = sha_256.digest();
            t = byteArrayXOR( t, u );
        }

        // generate return data
        var ret_val = new [KDF_RET_SIZE];
        ret_val[KDF_RET_KEY]    = t;
        ret_val[KDF_RET_SALT]   = kdf_salt;
        return ret_val;
    }

    // desc: returns the xor of both byte arrays
    // TODO handle arrays of different sizes
    // inputs:
    // - array_0    [bytes] first array
    // - array_1    [bytes] second array
    // returns:
    // - [bytes]    XOR result
    function byteArrayXOR( array_0, array_1 )
    {
        var result = new [array_0.size()]b;

        for( var i = 0; i < array_0.size(); ++i )
        {
            result[i] = array_0[i] ^ array_1[i];
        }

        return result;
    }

    // desc: converts bytes to hex
    function bytesToHex( bytes_in )
    {
        var converted_hex = StrUtl.convertEncodedString( bytes_in,
            {
                :fromRepresentation => StrUtl.REPRESENTATION_BYTE_ARRAY,
                :toRepresentation   => StrUtl.REPRESENTATION_STRING_HEX
            } );

        return converted_hex;
    }

}