using Toybox.Cryptography as Cryptography;

module Crypto
{
    const BLOCK_SIZE_BYTES  = 32;
    const IV_SIZE_BYTES     = 16;

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
    // - [bytes]    encrypted data
    function encrypt( iv_in, text_in, key_in )
    {
        var b_array = []b;
        var text_to_encrypt = AESPadData( text_in );
        b_array.addAll( text_to_encrypt );

        var aes_256_cipher = new Cryptography.Cipher(
            {
                :algorithm    => Cryptography.CIPHER_AES256,
                :mode         => Cryptography.MODE_CBC,
                :key          => key_in,
                :iv           => iv_in
            });

        var ecd = aes_256_cipher.encrypt( b_array );
        ecd.addAll( iv_in );
        return ecd;
    }

    function decrypt( data_in, key_in )
    {
        //get iv
        var iv_index = data_in.size() - IV_SIZE_BYTES;
        var data_iv = data_in.slice( iv_index, null );
        var ecd = data_in.slice( 0, iv_index );

        var aes_256_cipher = new Cryptography.Cipher(
            {
                :algorithm    => Cryptography.CIPHER_AES256,
                :mode         => Cryptography.MODE_CBC,
                :key          => key_in,
                :iv           => data_iv
            } );

        var dcd = aes_256_cipher.decrypt( ecd );

        var padding_length = dcd[dcd.size() - 1];
        dcd = dcd.slice( null, -padding_length );

        var text = "";
        for( var i = 0; i < dcd.size(); ++i )
        {
           text += dcd[i].toChar();
        }

        return dcd;
    }
}