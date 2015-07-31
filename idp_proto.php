<html>

<head>
<title>Proto IDP</title>
<link rel="stylesheet" type="text/css" href="mystyle.css">
</head>

<body>

<?php

# user is not authenticated
if(!isset($_COOKIE["session"])) {

    # provide a login form
	if(isset($_POST['returnUrl']) && isset($_POST['public_key']) && isset($_POST['nonce'])) {

		# user has to provide credentials
		if(!isset($_POST['username']) && !isset($_POST['password'])) {
?>

			<h1>Login mask:</h1>

			<form action="idp_proto.php" method="post">
				<input type="text" name="username" placeholder="username" /><br>
				<input type="text" name="password" placeholder="password" /><br>
				<input type="hidden" name="returnUrl" value="<?php echo $_POST['returnUrl']; ?>"/>
				<input type="hidden" name="public_key" value="<?php echo $_POST['public_key']; ?>"/>
				<input type="hidden" name="nonce" value="<?php echo $_POST['nonce']; ?>"/>
				<input type="submit" />
			</form>

<?php
		# user wants to login
		} else {

			$username = $_POST['username'];
			$password = $_POST['password'];

			# DEMO ONLY: do security checks for params depending on you DB

			if($username == "johndoe" && $password == "foobar") {

				setcookie('session', 'johndoe', (time() + 4000), '/', null, true, true);
?>

				<form action="idp_proto.php" method="post">
					<input type="hidden" name="returnUrl" value="<?php echo $_POST['returnUrl']; ?>"/>
					<input type="hidden" name="public_key" value="<?php echo $_POST['public_key']; ?>"/>
					<input type="hidden" name="nonce" value="<?php echo $_POST['nonce']; ?>"/>
				</form>
				<script type="text/javascript">window.onload = function () { document.forms[0].submit(); }</script>

<?php

			} else {
				# invalid credentials
				echo '<h1>Sorry, invalid username or password!</h1>';
			}

		}

	} else {
		echo '<h1>Sorry, missing information!</h1>';
	}

# user has a session cookie
} else {

	# user has a valid session cookie
	# DEMO ONLY: implement proper session management depending on your system
	if($_COOKIE['session'] == 'johndoe') {

		# DEMO ONLY: make sure to store your private key in a secure manner
		$privkey = get_private_key();

		# get params
		$c_nonce = $_POST['nonce'];
		$c_return_url = $_POST['returnUrl'];
		$c_pubkey = $_POST['public_key'];

		# 1. decrypt all input parameters
		openssl_private_decrypt(base64_decode($c_nonce), $nonce, $privkey);
		openssl_private_decrypt(base64_decode($c_return_url), $return_url, $privkey);

		# 2. get public key from Service Provider
		# DEMO ONLY: implement a function to read the public key from remote Service Provider
		$pubkey_url = base64_decode($c_pubkey);
		$pubkey = get_public_key_from_url($pubkey_url);

		# 3. get user from DB
		# DEMO ONLY
		$user = '{"Id":123456,"Username":"Johnny","Prename":"John","Surname":"Doe","EMail":"johnny@foo.com"}';

		# 4. build signature
		openssl_sign($user, $signature, $privkey, "RSA-SHA1");

		# 5. encrypting all output parameters
		$iv = substr(md5($nonce), 0, 32);
		$c_user = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $nonce, $user, MCRYPT_MODE_CBC, $iv);
		openssl_public_encrypt($nonce, $c_nonce, $pubkey);

		?>

		<form action="<?php echo $return_url ?>" method="post">
			<input type="text" name="Nonce" value="<?php echo base64_encode($c_nonce) ?> "/>
			<input type="text" name="User" value="<?php echo base64_encode($c_user) ?> "/>
			<input type="text" name="Signature" value="<?php echo base64_encode($signature) ?>"/>
		</form>

		<script type="text/javascript">window.onload = function () { document.forms[0].submit(); } </script>


		<?php

	# cookie is not valid
	} else {
		echo '<h1>Sorry, suspicious cookie!</h1>';
	}

}
?>

</body>

</html>
