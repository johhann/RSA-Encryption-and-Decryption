<?php

class Crypt 
{
    private array $config;
    private string $publicKey;
    private string $privateKey;

    public function __construct()
    {
        $this->publicKey = "-----BEGIN PUBLIC KEY-----\r\n" . chunk_split("Your-public-key"). "-----END PUBLIC KEY-----";
        $this->privateKey = "-----BEGIN PRIVATE KEY-----\n" . chunk_split("Your-private-key"). "-----END PRIVATE KEY-----";

        $this->config = array([
            'config' => './openssl.cnf',
            'default_md' => 'sha512',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
    }

    public function generate()
    {
        $keyPair = openssl_pkey_new($this->config);

        // private key
        openssl_pkey_export($keyPair, $privateKey, null, $this->config);

        // public key
        $public = openssl_pkey_get_details($keyPair);
        $publicKey = $public['key'];

        return [
            'private' => $privateKey,
            'public' => $publicKey
        ];
    }

    public function encrypt($data)
    {
        if (openssl_public_encrypt($data, $encrypted, $this->publicKey, OPENSSL_PKCS1_PADDING))
            $data = base64_encode($encrypted);
        else
            throw new \Exception('Unable to encrypt data. Perhaps it is bigger than the key size?');

        return $data;
    }

    public function decrypt($data)
    {
        if (openssl_private_decrypt(base64_decode($data), $decrypted, $this->privateKey, OPENSSL_PKCS1_PADDING))
            $data = $decrypted; 
        else
            $data = '';

        return $data;
    }
}