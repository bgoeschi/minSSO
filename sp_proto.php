<?php

# DEMO ONLY: the URL to the Service Provider
$serviceURL = 'http://myservice.com';

# DEMO ONLY: implement a function to read the public key from remote Identity Provider
$idp_pubkey = get_idp_public_key();

# DEMO ONLY: provide the path to your public key
$pubkey_url = 'http://path/to/my/public_key.pem';

# DEMO ONLY: create a random nonce on server side to prevent replay attacks
session_start();
if(!isset($_SESSION["nonce"])){
    $my_nonce = bin2hex(openssl_random_pseudo_bytes(16));
    $_SESSION["nonce"] = $my_nonce;
} else {
    $my_nonce = $_SESSION["nonce"];
}

# redirect unauthenticated user to Identity Provider
if(!isset($_POST["Nonce"])|| !isset($_POST["User"]) || !isset($_POST["Signature"])){

    openssl_public_encrypt($my_nonce, $cNonce, $idp_pubkey);
    openssl_public_encrypt($serviceURL, $cServiceURL, $idp_pubkey);

?>

    <form action="<?php echo $idp_login_service_address ?>" method="post">
    <input type="hidden" name="nonce" value="<?php echo base64_encode($cNonce); ?>" />
    <input type="hidden" name="returnUrl" value="<?php echo base64_encode($cServiceURL); ?>" />
    <input type="hidden" name="public_key" value="<?php echo base64_encode($pubkey_url); ?>" />
    </form>
    <script type="text/javascript"> window.onload = function () { document.forms[0].submit(); } </script>

<?php

# received a user authentication: decrypt and verify it
} else {

    # 1. decrypt nonce and verify authenticity
    openssl_private_decrypt(base64_decode($_POST["Nonce"]), $nonce, $sp_privkey);
    if ($nonce == $my_nonce) {

        # 2. decrypt other output parameters (user and signature)
        $iv = substr(md5($my_nonce), 0, 32);
        $user = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $my_nonce, base64_decode($_POST["User"]), MCRYPT_MODE_CBC, $iv);

        # 3. check signature of IDP
        $signature = $_POST['Signature'];

        $verified = openssl_verify($user, base64_decode($signature), $idp_pubkey, "RSA-SHA1");

        # 4. signature is verified and has not thrown an error
        if ($verified == 1) {

            # DEMO ONLY: do something with the authenticated user
            $json = (array) json_decode($user);
            echo "<h1>Hello, " . $json['Username'] . " !</h1>";

        } else {
            echo "<h1>Spoofing alert!</h1>";
        }
    } else {
        echo "<h1>Spoofing alert!</h1>";
    }
    session_destroy();
}

?>
