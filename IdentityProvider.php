<?php

class IdentityProvider {

    // the keys
    private $idp_private_key = "";
    private $sp_public_key = "";

    // cryptographic attributes with default values
    private $signature_mode = "RSA-SHA256";
    private $encryption_mode = MCRYPT_RIJNDAEL_256;
    private $block_mode = MCRYPT_MODE_CBC;
    private $iv_start = 0;
    private $iv_length = 32;

    /**
     * @summary
     *      method called by IDP when the user has successfully authenticated
     * @param $idp_private_key
     * @param $sp_public_key
     * @param $user_json
     * @param $c_nonce
     * @param $c_url
     * @return array
     *      'c_nonce' => nonce encrypted with pubkey of SP
     *      'c_user_info' => user info encrypted with nonce
     *      'signature' => signature of the user info
     *      'return_url' => return url to send the above information
     */
    function prepare_redirect($idp_private_key, $sp_public_key, $user_json, $c_nonce, $c_url) {
        $this->set_private_key($idp_private_key);
        $this->set_public_key($sp_public_key);

        $nonces = $this->derive_nonce($c_nonce);
        $return_url = $this->derive_returnURL($c_url);
        $c_user_info = $this->encrypt_user_info($user_json, $nonces['nonce']);
        $signature = $this->build_signature($user_json);

        return array(
            "c_nonce" => $nonces['c_nonce'],
            "c_user_info" => $c_user_info,
            "signature" => $signature,
            "return_url" => $return_url
        );
    }

    /*
     * Helper functions
     */
    function set_private_key($key_stream) {
        $this->idp_private_key = openssl_get_privatekey($key_stream);
    }

    function set_public_key($key_stream) {
        $this->sp_public_key = openssl_get_publickey($key_stream);
    }

    function derive_nonce($c_nonce) {
        // decrypt nonce
        openssl_private_decrypt(base64_decode($c_nonce), $tmp_nonce, $this->idp_private_key);

        // encrypt nonce with public key of the SP
        openssl_public_encrypt($tmp_nonce, $tmp_c_nonce, $this->sp_public_key);

        return array(
            "nonce" => $tmp_nonce,
            "c_nonce" => base64_encode($tmp_c_nonce)
        );
    }

    function derive_returnURL($c_url) {
        openssl_private_decrypt(base64_decode($c_url), $tmp_url, $this->idp_private_key);
        return $tmp_url;
    }

    function encrypt_user_info($json_string, $nonce) {
        // encrypt user info
        $iv = substr(md5($nonce), $this->iv_start, $this->iv_length);
        $c_user = mcrypt_encrypt($this->encryption_mode, $nonce, $json_string, $this->block_mode, $iv);

        return base64_encode($c_user);
    }

    function build_signature($user_info) {
        openssl_sign($user_info, $tmp_signature, $this->idp_private_key, $this->signature_mode);
        return base64_encode($tmp_signature);
    }

    /*
     * Setter for encryption configuration
     */
    public function setSignatureMode($signature_mode) {
        $this->signature_mode = $signature_mode;
    }

    public function setEncryptionMode($encryption_mode) {
        $this->encryption_mode = $encryption_mode;
    }

    public function setBlockMode($block_mode) {
        $this->block_mode = $block_mode;
    }

    public function setIvStart($iv_start) {
        $this->iv_start = $iv_start;
    }

    public function setIvLength($iv_length) {
        $this->iv_length = $iv_length;
    }


}
