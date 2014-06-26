#!/usr/local/bin/php
<?php
ini_set('display_errors', 'Off');
error_reporting(0);
$version = "1.0 (25/06/14)";
#######################################################################
# Author: Jeroen Wierda (jeroen@wierda.com)
# Version: 1.0 (25/06/14)
#
# A small script to change passwords for DA users, or e-mail addresses,
# or FTP accounts. This script can reset either all accounts, or a
# single domain, or a single (DA/e-mail/ftp) user.
#
# This script will attempt to download the following required file if
# it is not found in the same directory. But you can manually download
# it as well:
#
# http://files.directadmin.com/services/all/httpsocket/httpsocket.php
#
# Usage:
#   Change the password of one user:
#      ./da_changepass.php --user <username> <optional password>
#      If no password is given, a random one will be generated
#
#   Change the passwords for all users except te admin user:
#      ./da_changepass.php --alluser
#
#   Change the e-mail password for all e-mail accounts on the server:
#      ./da_changepass.php --allmail
#
#   Change all e-mail passwords for a specific domain:
#      ./da_changepass.php --mail <domainname>
#
#   Change the e-mail password for a specific e-mail address:
#      ./da_changepass.php --mail <e-mail address> <optional password>
#      If no password is given, a random one will be generated
#
#   Change the ftp account password for all ftp accounts on the server:
#      ./da_changepass.php --allftp
#
#   Change all ftp account passwords for a specific domain:
#      ./da_changepass.php --ftp <domainname>
#
#   Change the ftp account password for a specific account:
#      ./da_changepass.php --ftp <ftpuser@domain> <optional password>
#      If no password is given, a random one will be generated
#
#   Display a list of ftp or e-mail accounts:
#      ./da_changepass.php --list <ftp | mail> <optional domain>
#
#   Send a test e-mail:
#      ./da_changepass.php --mailtest
#
# ---------------------------------------------------------------------
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#######################################################################

## Script edit check
$scriptedited="N"; // Change to Y to indicate that the variables in this script have been checked and edited

## Server IP, port and admin user/password. The $server_ssl parameter indicates if DirectAdmin loads with or without https
$server_ip=""; // if this is left empty, you will be asked for the target server IP address
$server_port="2222"; // if this is left empty, you will be asked for the server port every time.
$server_login=""; // if this is left empty or "adminuser", you will be asked for the admin or reseller user
$server_pass=""; // if this is left empty or "adminpass", you will be asked for the password every time you run this script.
$server_ssl="N"; // if this is left empty, you will be asked if the target DA server uses ssl.

## Other parameters
$passlength = "10"; // length of the new passwords
$passchars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"; //the characters the password will be constructed from
$adminuser="admin"; // the admin user. This password is not changed with --alluser
$displayempty="Y"; // if set to Y, domains which return no value (have no e-mail addresses of ftp accounts) will be displayed in the output listing.
$sendsummary="Y"; // if a summary should be sent to the e-mail address indicated in $sendsummaryaddress. (Y or N)
$sendinfosummary="Y"; // if a summary of information (--list) should be sent to the e-mail address indicated in $sendsummaryaddress. (Y or N)
$sendsummaryaddress="email@address.ext"; // where to send the summary to
$mailfrom="email@address.ext"; // the mail address the summary and user notifications are coming from
$sendemailtouser="Y"; // send an e-mail to the affected DirectAdmin user(s). (Y or N)

## SMTP parameters. If $usesmtp is N, PHP's internal mail function will be used. If you set $usesmtp to Y, you can make the script send a test e-mail (--mailtest) to the address set in $sendsummaryaddress to make sure it is set up correctly
$usesmtp="N"; //Y requires PHPMailer (https://github.com/PHPMailer/PHPMailer). If Y, use the enter the mailserver information below
$SmtpServer="mail.server.ext"; // Smtp server address/name
$SmtpPort=""; //if left empty, the script will try to figure out the port by itself
$SmtpSecure="tls"; // either tls, ssl, or no value at all
$SmtpUser=""; // smtp username
$SmtpPass=""; // smtp password
$phpmailer="PHPMailer"; // PHPMailer path without trailing slash.

#######################################################################
# The parameters below are the mail subjects and bodies of mail that
# will be send to users if their DA account, e-mail, or ftp passwords
# have been changed. The body parameters have placeholders that will be
# converted before the e-mail is sent. $sendemailtouser should be Y .
#######################################################################

## DA Account
$mailsubject="Forced password change";

## Possible mailbody placeholders that will be converted to user info: <USERNAME>, <PASSWORD> and <DOMAIN>
$mailbody="Dear client,

Due to security circumstances, we had to change your DirectAdmin user password.

Username : <USERNAME>
Password : <PASSWORD>
Domain   : <DOMAIN> 

Kind regards,
your hosting provider";

## Mail account
$mailuser_mailsubject="Forced e-mail password change";

## Possible mailbody placeholders that will be converted to user info: <EMAILPASSWORDLIST> <DOMAIN>
$mailuser_mailbody="Dear client,

Due to security circumstances, we had to change some, or all e-mail address passwords for <DOMAIN>. The following addresses have a new password:

<EMAILPASSWORDLIST>

Kind regards,
your hosting provider";

## FTP account
$ftpuser_mailsubject="Forced ftp account password change";

## Possible ftp mailbody placeholders that will be converted to user info: <FTPPASSWORDLIST> <DOMAIN>
$ftpuser_mailbody="Dear client,

Due to security circumstances, we had to change some, or all ftp account passwords for <DOMAIN>. The following ftp accounts have a new password:

<FTPPASSWORDLIST>

Kind regards,
your hosting provider";

## Nothing needs to be changed below this point
if(php_sapi_name() != "cli") {
	echo "Error: This script can only be executed from the commandline interface.";
	exit(1);
}

if(strtoupper($scriptedited) != "Y"){
	$notedited = "There are variables that need to be changed near the top of this script. For example the variables indicating if a mail need to be sent, and what the mail contents need to be. Once done, change the \$scriptedited variable to \"Y\".\r\n\r\n";
}

if ($argc < 2 || ($argv[1] != "--user" && $argv[1] != "--alluser" && $argv[1] != "--mail" && $argv[1] != "--allmail" && $argv[1] != "--ftp" && $argv[1] != "--allftp" && $argv[1] != "--list" && $argv[1] != "--mailtest")){
	echo "Password Changer - version $version\r\nWritten by Jeroen Wierda (jeroen@wierda.com)\r\n\r\n" . $notedited . "Usage:\r\n  Change the password of one user:\r\n    $argv[0] --user <username> <optional password>\r\n    If no password is given, a random one will be generated\r\n\r\n  Change the passwords for all users except te admin user:\r\n    $argv[0] --alluser\r\n\r\n  Change the e-mail password for all e-mail accounts on the server:\r\n    $argv[0] --allmail\r\n\r\n  Change all e-mail passwords for a specific domain:\r\n    $argv[0] --mail <domainname>\r\n\r\n  Change the e-mail password for a specific e-mail address:\r\n    $argv[0] --mail <e-mail address> <optional password>\r\n    If no password is given, a random one will be generated\r\n\r\n  Change the ftp account password for all ftp accounts on the server:\r\n    $argv[0] --allftp\r\n\r\n  Change all ftp account passwords for a specific domain:\r\n    $argv[0] --ftp <domainname>\r\n\r\n  Change the ftp account password for a specific account:\r\n    $argv[0] --ftp <ftpuser@domain> <optional password>\r\n    If no password is given, a random one will be generated\r\n\r\n  Display a list of ftp or e-mail accounts:\r\n    $argv[0] --list <ftp | mail> <optional domain>\r\n\r\n  Send a test e-mail:\r\n    $argv[0] --mailtest\r\n\r\n\r\n";
	exit(1);
}

if($notedited != ""){
	echo "\r\nError: " . $notedited;
	exit(1);
}

if($argv[1] != "--mailtest"){
	if($server_ip == "" || !filter_var($server_ip, FILTER_VALIDATE_IP)){
		echo "The server IP is empty or invalid. What is the IP address of the server?: ";
		$waiting = fopen ("php://stdin","r");
		$cli_entry = trim(fgets($waiting));
		if(!filter_var($cli_entry, FILTER_VALIDATE_IP)){
			echo "No valid IP address given. Script will exit now.\r\n";
			exit(1);
		}else{
			$server_ip = $cli_entry;
		}
	}

	if($server_port == "" || !ctype_digit($server_port)){
		echo "The DirectAdmin server port is empty or invalid. What is the port number?: ";
		$waiting = fopen ("php://stdin","r");
		$cli_entry = trim(fgets($waiting));
		if(!ctype_digit($cli_entry)){
			echo "No valid DA port number given. Script will exit now.\r\n";
			exit(1);
		}else{
			$server_port = $cli_entry;
		}
	}

	if($server_ssl == "" || !ctype_digit($server_ssl)){
		echo "Is DirectAdmin reachable over SSL? (Y/N): ";
		$waiting = fopen ("php://stdin","r");
		$cli_entry = strtoupper(trim(fgets($waiting)));
		if($cli_entry != "Y" && $cli_entry != "N"){
			echo "No Y or N received. Script will exit now.\r\n";
			exit(1);
		}else{
			$server_ssl= $cli_entry;
		}
	}

	if($server_login == "" || $server_login == "adminuser"){
		echo "The admin user is not set. What is the adminuser?: ";
		$waiting = fopen ("php://stdin","r");
		$cli_entry = trim(fgets($waiting));
		if($cli_entry == ""){
			echo "No admin user given. Script will exit now.\r\n";
			exit(1);
		}else{
			$server_login = strtolower($cli_entry);
		}
	}

	if($server_pass == "" || $server_pass == "adminpass"){
		echo "Password for $server_login is empty or default. What is the password for $server_login?: ";
		$waiting = fopen ("php://stdin","r");
		$cli_entry = trim(fgets($waiting));
		if($cli_entry == ""){
			echo "No password given. Script will exit now.\r\n";
			exit(1);
		}else{
			$server_pass = $cli_entry;
		}
	}

	if(!file_exists("httpsocket.php")){
		$currdir = getcwd();

		$cdest = fopen ("$currdir/httpsocket.php", 'w+');
		$url = "http://files.directadmin.com/services/all/httpsocket/httpsocket.php";
		$url = curl_init(str_replace(" ","%20",$url));

		curl_setopt($url, CURLOPT_TIMEOUT, 50);
		curl_setopt($url, CURLOPT_FILE, $cdest);
		curl_setopt($url, CURLOPT_FOLLOWLOCATION, true);

		$data = curl_exec($url);
		curl_close($url);
	}

	function generate_password( $length = 10 ) {
		global $passchars;
		$password = substr( str_shuffle( $passchars ), 0, $length );
		return $password;
	}

	include 'httpsocket.php';

	$sock = new HTTPSocket;
	if (strtoupper($server_ssl) == 'Y'){
		$sock->connect("ssl://".$server_ip, $server_port);
	}else{
		$sock->connect($server_ip, $server_port);
	}

	$sock->set_login($server_login,$server_pass);

	function test_connection(){
		global $sock;

		$sock->set_method('POST');

		$sock->query('/CMD_API_LOGIN_TEST');

		if($sock->error[0]){
			echo "Error: Can't create socket connection. Check if the server_ssl and server_port parameter is set correctly.\r\n";
			exit(1);
		}

		$result = $sock->fetch_parsed_body();

		if($result['text'] != "Login OK"){
			echo "Error: Admin user or password possibly incorrect\r\n";
			exit(1);
		}
	}

	test_connection();
}

if(file_exists("$phpmailer/PHPMailerAutoload.php") && strtoupper($usesmtp) == "Y") {
	require "$phpmailer/PHPMailerAutoload.php";
}elseif(!file_exists("$phpmailer/PHPMailerAutoload.php") && strtoupper($usesmtp) == "Y"){
	echo "Sending mail through smtp is enabled, but path to PHPMailer is not found\r\n";
	exit(1);
}

function mailout($to, $subject, $message) {

	global $SmtpServer, $SmtpUser, $SmtpPass, $mailfrom, $mailsent, $SmtpPort, $SmtpSecure, $mailerror;

	$mail = new PHPMailer;
	$mail->ContentType = 'text/plain';
	$mail->IsHTML(false);

	$mail->isSMTP();
	$mail->Host = $SmtpServer;
	$mail->SMTPAuth = true;
	$mail->Username = $SmtpUser;
	$mail->Password = $SmtpPass;
	$mail->SMTPSecure = $SmtpSecure;

	if($SmtpPort != ""){
		$mail->Port = $SmtpPort;
	}

	$mail->XMailer = ' ';
	$mail->From = $mailfrom;
	$mail->FromName = $mailfrom;
	$mail->addAddress($to, $to);
	$mail->addReplyTo($mailfrom, $mailfrom);

	$mail->Subject = $subject;
	$mail->Body    = $message;

	if(!$mail->send()) {
		$mailerror = 'Mailer Error: ' . $mail->ErrorInfo;
	} else {
		$mailsent = 1;
	}
}

function change_password($username,$pass) {
	global $passlength, $adminuser, $sendemailtouser, $sendsummary, $sendsummaryaddress, $mailfrom, $mailsubject, $mailbody, $total, $total_err, $sock, $sock2, $usesmtp, $SmtpServer, $SmtpUser, $SmtpPass, $SmtpPort, $SmtpSecure,$mailsent,$mailerror;

	$sock->set_method('POST');

	$sock->query('/CMD_API_USER_PASSWD',
	array(
	'username' => $username,
	'passwd' => $pass,
	'passwd2' => $pass
	));

	if($sock->error[0]){
		echo "Error: Can't create socket connection. Check if the server_ssl and server_port parameter is set correctly.\r\n";
		exit(1);
	}

	$result = $sock->fetch_parsed_body();
	## The following check is inserted because with remote calls to the api, CMD_API_USER_PASSWD returns empty results half the time.
	## A lengthy check with DA in debug mode reveals that passwords are correctly updated anyway. CMD_API_VERIFY_PASSWORD is used to check the new passwords.

	$sock->set_method('GET');

	$sock->query('/CMD_API_VERIFY_PASSWORD',
	array(
	'user' => $username,
	'passwd' => $pass
	));

	$result_ver = $sock->fetch_parsed_body();

	if($result_ver['valid'] != 1){
		$response = "$username password set to $pass, but verification failed";
		$changeok = 0;
	}else{
		$response = "$username password set to $pass";
		$changeok = 1;
	}

	if($changeok == 1){
		if(strtoupper($sendemailtouser) == "Y" && $changeok == 1){
			$sock->set_method('GET');

			$sock->query('/CMD_API_SHOW_USER_CONFIG',
			array(
			'user' => $username
			));

			$result = $sock->fetch_parsed_body();

			if($result['email'] == ""){
				echo "Error retrieving user (e-mail) details.\r\n";
			}else{
				$email = $result['email'];

				$mailbody_temp = str_replace("<PASSWORD>",$pass,$mailbody);
				$mailbody_temp = str_replace("<USERNAME>",$result['username'],$mailbody_temp);
				$mailbody_temp = str_replace("<DOMAIN>",$result['domain'],$mailbody_temp);

				if(strtoupper($usesmtp) == "Y"){
					mailout($email, $mailsubject, $mailbody_temp);
					if($mailsent == 1){
						$response = $response . " - Password sent to $email";
					}else{
						$response = $response . " - $mailerror";
					}
				}else{
					$to	 = $email;
					$subject = $mailsubject;
					$message = $mailbody_temp;
					$headers = "From: $mailfrom" . "\r\n" .
					"Reply-To: $mailfrom";
					mail($to, $subject, $message, $headers);
					$response = $response . " - Password sent to $email";
				}

				unset($mailerror,$mailsent,$mailbody_temp);

			}
		}else{
			$response =  $response;
		}
	}else{
		$sock->set_method('GET');

		$sock->query('/CMD_API_SHOW_USER_CONFIG',
		array(
		'user' => $username
		));

		$result = $sock->fetch_parsed_body();

		if($result['suspended'] == "yes"){
			$response = $response . " - User $username is suspended!";
			$error = "$username is suspended. Password not e-mailed to user.";
		}else{
			$response = $response . " - Unknown reason.";
			$error = "$username password update was attempted, but could not be verified.";
		}
	}

	echo $response . " \r\n";

	if($total == ""){
		$total = $response . " \r\n";
	}else{
		$total .= $response . " \r\n";
	}

	if($total_err == ""){
		$total_err = $error . " \r\n";
	}else{
		$total_err .= $error . " \r\n";
	}
}

if($argv[1] == "--allmail" || $argv[1] == "--mail" || $argv[1] == "--allftp" || $argv[1] == "--ftp" || $argv[1] == "--list"){
	$sock->set_method('GET');

	$sock->query('/CMD_API_SHOW_USER_CONFIG',
	array(
	'user' => $server_login
	));

	$result = $sock->fetch_parsed_body();

	if($result['usertype'] == "user"){
		echo "Error: you have no authority to view or update data.\r\n";
		exit(1);
	}

	$sock->set_method('POST');

	$sock->query('/CMD_API_DOMAIN_OWNERS');

	if($sock->error[0]){
		echo "Error: Can't create socket connection. Check if the server_ssl and server_port parameter is set correctly.\r\n";
		exit(1);
	}

	$result = $sock->fetch_parsed_body();

	if(empty($result)){
		echo "This server has no domain names.\r\n";
		exit(0);
	}

	if(strpos($argv[1], "mail") !== FALSE || ($argv[1] == "--list" && $argv[2] == "mail")){
		$type = "mail";
		$atype = "POP";
	}elseif(strpos($argv[1], "ftp") !== FALSE || ($argv[1] == "--list" && $argv[2] == "ftp")){
		$type = "ftp";
		$atype = "FTP";
	}

	if($argv[2]){
		$argv[2] = strtolower($argv[2]);
	}
	if(($argv[2] != "" && strpos($argv[2], "@") === FALSE) && $argv[1] == "--mail"){
		foreach ($result as $domkey => $domvalue) {
			if(str_replace("_",".",$domkey) != $argv[2]){
				unset($result[$domkey]);
			}
		}
		if(!$result){
			echo "Error: Domain {$argv[2]} not found.\r\n\r\n";
			exit(1);
		}

	}elseif(($argv[1] == "--list" && $argv[2] == "mail") || ($argv[1] == "--list" && $argv[2] == "ftp")){
		$showinfo = 1;
		$sendemailtouser = "N";
		$sendsummary = "N";
		$t = 0;

		if($argv[3] != ""){
			$argv[3] = strtolower($argv[3]);
			$domserve = $argv[3];
			foreach ($result as $domkey => $domvalue) {
				if(str_replace("_",".",$domkey) != $argv[3]){
					unset($result[$domkey]);
				}
			}
			if(!$result){
				echo "Error: Domain {$argv[3]} not found.\r\n\r\n";
				exit(1);
			}
		}else{
			$domserve = "this server";
		}
	}elseif(($argv[2] != "" && strpos($argv[2], "@") !== FALSE) && $argv[1] == "--mail"){
		$domonly = explode("@", $argv[2]);
		foreach ($result as $domkey => $domvalue) {
			if(str_replace("_",".",$domkey) != $domonly[1]){
				unset($result[$domkey]);
			}else{
				$mailtrue = 1;
				if($argv[3] != "" && strlen($argv[3]) >= 5){
					$custompass = $argv[3];
				}elseif($argv[3] != "" && strlen($argv[3]) < 5){
					echo "Error: a custom set password should be at least 5 characters \r\n";
					exit(1);
				}
			}
		}
		if(!$result){
			echo "Error: Domain {$domonly[1]} not found.\r\n\r\n";
			exit(1);
		}
	}elseif(($argv[2] != "" && strpos($argv[2], "@") === FALSE) && $argv[1] == "--ftp"){
		foreach ($result as $domkey => $domvalue) {
			if(str_replace("_",".",$domkey) != $argv[2]){
				unset($result[$domkey]);
			}
		}
		if(!$result){
			echo "Error: Domain {$argv[2]} not found.\r\n\r\n";
			exit(1);
		}
	}elseif(($argv[2] != "" && strpos($argv[2], "@") !== FALSE) && $argv[1] == "--ftp"){
		$domonly = explode("@", $argv[2]);
		foreach ($result as $domkey => $domvalue) {
			if(str_replace("_",".",$domkey) != $domonly[1]){
				unset($result[$domkey]);
			}else{
				$ftptrue = 1;
				if($argv[3] != "" && strlen($argv[3]) >= 5){
					$custompass = $argv[3];
				}elseif($argv[3] != "" && strlen($argv[3]) < 5){
					echo "Error: a custom set password should be at least 5 characters \r\n";
					exit(1);
				}
			}
		}
		if(!$result){
			echo "Error: Domain $domonly[1] not found.\r\n\r\n";
			exit(1);
		}
	}elseif($argv[1] == "--all$type" && $argv[2] != ""){
		echo "Error: Use --all$type without any other arguments.\r\n\r\n";
		exit(1);
	}elseif($argv[1] == "--$type" && $argv[2] == ""){
		echo "Error: Use --$type with either a domain name or e-mail address.\r\n\r\n";
		exit(1);
	}elseif($argv[1] == "--list" && ($argv[2] != "mail" || $argv[2] != "ftp")){
		echo "Error: Use --list with arguments mail or ftp\r\n\r\n";
		exit(1);
	}

	foreach ($result as $key => $value) {
		$domain = str_replace("_",".",$key);
		$sock->set_login($server_login . "|" . $value,$server_pass);
		$sock->set_method('GET');
		$sock->query("/CMD_API_$atype",
		array(
		'action' => 'list',
		'domain' => $domain,
		'api' => 'yes'
		));
		$result = $sock->fetch_parsed_body();

		$sock->set_login($server_login,$server_pass);
		$sock->set_method('GET');

		$sock->query('/CMD_API_SHOW_USER_CONFIG',
		array(
		'user' => $value
		));

		$domuser_result = $sock->fetch_parsed_body();

		$sock->set_login($server_login . "|" . $value,$server_pass);

		if($domuser_result['suspended'] == "yes"){
			$user_suspended = 1;
			$domainline = "Domain: " . str_replace("_",".",$key) . " - User: " . $value . $user_suspended_text . " (suspended)\r\n";
		}else{
			$domainline = "Domain: " . str_replace("_",".",$key) . " - User: " . $value . "\r\n";
		}

		if($mailtrue == 1){
			foreach ($result['list'] as $mailkey => $mailuser) {
				if( $mailuser != $domonly[0]){
					unset($result['list'][$mailkey]);
				}else{

				}
			}
			if(!$result['list']){
				echo "Error: Mail address {$argv[2]} not found.\r\n\r\n";
				exit(1);
			}
		}

		if($ftptrue == 1){
			foreach ($result as $ftpuser => $ftplocation) {
				$ftptemp = explode("@", $ftpuser);
				$ftptemp[1] = str_replace("_",".",$ftptemp[1]);
				$ftptemp = implode("@",$ftptemp);

				if($argv[2] != $ftptemp){
					unset($result[$ftpuser]);
				}else{

				}
			}

			if(!$result){
				echo "Error: FTP account {$argv[2]} not found.\r\n\r\n";
				exit(1);
			}

		}

		if($result['list']){
			echo $domainline;
			if($total == "" && $showinfo == 1){
				$total = $domainline;
			}else{
				$total .= $domainline;
			}
			unset($domainline);
			$i = 1;
			if($showinfo == 1){
				foreach ($result['list'] as $evalue) {
					$response = $evalue . "@" . $domain;
					echo "    " . $response . "\r\n";
					$total .= $response . "\r\n";
					$t++;
				}
			}else{
				foreach ($result['list'] as $evalue) {
					if($custompass != ""){
						$mpass = $custompass;
					}else{
						$mpass = generate_password($passlength);
					}
					$sock->query("/CMD_API_POP",
					array(
					'domain'=>$domain,
					'action'=>'modify',
					'user'=>$evalue,
					'passwd'=>$mpass,
					'passwd2'=>$mpass,
					'api' => 'yes'
					));
					$result = $sock->fetch_parsed_body();

					if ($result['error'] != "0"){
						$error = $evalue . "@" . $domain . " failed to update";
					}else{
						$response = $evalue . "@" . $domain . " password changed to " . $mpass . "\r\n";
					}

					echo "    " . $response;

					if($mtotal == ""){
						$mtotal = $response;
					}else{
						$mtotal .= $response;
					}
					if($total == ""){
						$total = $response;
					}else{
						$total .= $response;
					}
				}
			}
			$i++;
		}elseif($result && $type == "ftp"){

			$i = 1;
			if($showinfo == 1){
				foreach ($result as $ftpkey => $evalue) {
					if(strpos($ftpkey,"@") === FALSE){
						continue; //skip domain ftp accounts because those are reset with the DA user
					}
					echo $domainline;
					if($total == ""){
						$total = $domainline;
					}else{
						$total .= $domainline;
					}
					unset($domainline);
					$ftpuser = explode("@",$ftpkey);
					$response = $ftpuser[0] . "@" . $domain;
					echo "    " . $response . "\r\n";
					$total .= $response . "\r\n";
					$i++;
					$t++;
				}

			}else{
				foreach ($result as $ftpkey => $evalue) {

					$ftpuser = explode("@",$ftpkey);

					$sock->query("/CMD_API_FTP_SHOW",
					array(
					'domain'=>$domain,
					'user'=>$ftpuser[0],
					'api' => 'yes'
					));
					$result = $sock->fetch_parsed_body();

					if(strpos($result['fulluser'],"@") === FALSE){
						continue; //skip domain ftp accounts because those are reset with the DA user
					}

					echo $domainline;
					if($total == ""){
						$total = $domainline;
					}else{
						$total .= $domainline;
					}
					unset($domainline);

					if(!$result['fulluser']){
						echo "An error occurred while trying to change the ftp password for this domain.\r\n";
						continue;
					}

					if($result['type'] == "custom"){
						$custompath = 1;
					}else{
						$custompath = 0;
					}

					$fulluser = $result['fulluser'];
					if($custompass != ""){
						$mpass = $custompass;
					}else{
						$mpass = generate_password($passlength);
					}

					if($custompath == 1){
						$sock->query("/CMD_API_FTP",
						array(
						'domain'=>$domain,
						'action'=>'modify',
						'user'=>$result['user'],
						'passwd'=>$mpass,
						'passwd2'=>$mpass,
						'type'=>$result['type'],
						'custom_val'=>$result['path'],
						'api' => 'yes'
						));
					}else{
						$sock->query("/CMD_API_FTP",
						array(
						'domain'=>$domain,
						'action'=>'modify',
						'user'=>$result['user'],
						'passwd'=>$mpass,
						'passwd2'=>$mpass,
						'type'=>$result['type'],
						$custom,
						'api' => 'yes'
						));
					}
					$result = $sock->fetch_parsed_body();

					if ($result['error'] != "0"){
						$error = $fulluser . " failed to update";
					}else{
						$response = $fulluser . " ftp password changed to " . $mpass . "\r\n";
					}

					echo "    " . $response;

					if($mtotal == ""){
						$mtotal = $response;
					}else{
						$mtotal .= $response;
					}
					if($total == ""){
						$total = $response;
					}else{
						$total .= $response;
					}
					$i++;
				}
			}
			if($i == 1){
				if(strtoupper($displayempty) == "Y"){
					echo $domainline;
					unset($domainline);
				}

				#$error = "This domain has no user additional ftp accounts\r\n";
				#echo "    " . $error;
				$i = 0;
			}
		}else{
			if(strtoupper($displayempty) == "Y"){
				echo $domainline;
				unset($domainline);
			}
			#$error = "This domain has no user e-mail addresses\r\n";
			#echo "    " . $error;
			$i = 0;
		}
		if($mtotal != "" && $i >= 1){
			if ($domuser_result['email'] == ""){
				echo "Error retrieving user details.\n";
			}elseif($domuser_result['suspended'] == "yes"){
				#echo "  List of changes NOT e-mailed because $value is suspended! \r\n";
				$error = $value . " is suspended. Password(s) for " . $domain . " were not sent.";
			}else{
				if(strtoupper($sendemailtouser) == "Y"){
					$email = $domuser_result['email'];

					if($type == "mail"){
						$mailuser_mailbody_temp = str_replace("<DOMAIN>",$domain,$mailuser_mailbody);
						$mailuser_mailbody_temp = str_replace("<EMAILPASSWORDLIST>",$mtotal,$mailuser_mailbody_temp);
						$subject = $mailuser_mailsubject;
						$message = $mailuser_mailbody_temp;
					}elseif($type == "ftp"){
						$ftpuser_mailbody_temp = str_replace("<DOMAIN>",$domain,$ftpuser_mailbody);
						$ftpuser_mailbody_temp = str_replace("<FTPPASSWORDLIST>",$mtotal,$ftpuser_mailbody_temp);
						$subject = $ftpuser_mailsubject;
						$message = $ftpuser_mailbody_temp;
					}

					if(strtoupper($usesmtp) == "Y"){
						mailout($email, $subject, $message);
						if($mailsent == 1){
							echo "  List of changes sent to the DirectAdmin user: $email \r\n";
						}else{
							echo "  $mailerror \r\n";
						}
					}else{
						$to	 = $email;
						$headers = "From: $mailfrom" . "\r\n" .
						"Reply-To: $mailfrom";
						mail($to, $subject, $message, $headers);
						echo "  List of changes sent to the DirectAdmin user: $email \r\n";
					}

					unset($mailerror,$mailsent,$mtotal,$mailuser_mailbody_temp,$ftpuser_mailbody_temp);

				}else{
					#echo "  List of changes was NOT sent to the DirectAdmin user. \r\n";
				}

			}

			if($total_err == ""){
				$total_err = $error . " \r\n";
			}else{
				$total_err .= $error . " \r\n";
			}
			unset($error, $user_suspended);

		}
	}

	if($argv[1] == "--list" && $t >= 1){
		echo "\r\nThere are $t custom $type accounts on $domserve (main $type accounts are not displayed). \r\n";
	}

}elseif($argv[1] == "--user"){
	if($argv[1] == "--user" && $argv[2] == ""){
		echo "Error: Use --user with a username and optional password.\r\n\r\n";
		exit(1);
	}
	$username=strtolower($argv[2]);

	$sock->set_method('GET');

	//CMD_API_USER_EXISTS would be best here, but that funct was just created in 1.4
	$sock->query('/CMD_API_SHOW_USER_CONFIG',
	array(
	'user' => $username
	));

	$result = $sock->fetch_parsed_body();

	if(isset($result['name'])){

		if($argv[3] != ""){
			$pass=$argv[3];
		}else{
			$pass = generate_password($passlength);
		}
		change_password($username,$pass);
	}else{
		echo "This user does not exist.\r\n";
	}
}elseif($argv[1] == "--alluser"){
	if($argv[1] == "--alluser" && $argv[2] != ""){
		echo "Error: Use --alluser without any other arguments.\r\n\r\n";
		exit(1);
	}

	$sock->set_method('POST');

	$sock->query('/CMD_API_SHOW_ADMINS');
	$resulta = $sock->fetch_parsed_body();

	if($resulta['list']){
		foreach($resulta['list'] as $key => $value){
			if($value == $adminuser){
				unset($resulta['list'][$key]);
			}
		}
	}else{
		$resulta['list'] = array();
		$noadmins = 1;
	}

	$sock->query('/CMD_API_SHOW_RESELLERS');
	$resultr = $sock->fetch_parsed_body();

	if(!$resultr['list']){
		$resultr['list'] = array();
		$noresellers = 1;
	}

	if($noadmins == 1 && $noresellers == 1){
		$sock->set_method('GET');
		$sock->query('/CMD_API_SHOW_USERS',
		array(
		'reseller'=>$server_login
		));

		$resultu = $sock->fetch_parsed_body();
	}else{
		$sock->query('/CMD_API_SHOW_ALL_USERS');
		$resultu = $sock->fetch_parsed_body();
	}

	if(!$resultu['list']){
		$resultu['list'] = array();
	}

	$amerged = array_merge($resulta['list'], $resultr['list'], $resultu['list']);

	if(count($amerged) !== 0){

		foreach($amerged as $username){
			$pass = generate_password($passlength);
			change_password($username,$pass);
		}
		
	}else{
		echo "This server has no users (or no users that you have authority over). No passwords changed.\r\n";
	}
}elseif($argv[1] == "--mailtest"){
	$to	 = $sendsummaryaddress;
	$subject = "da_changepass testmail";
	$message = "This is a test mail from the da_changepass script.\r\n";

	if(strtoupper($usesmtp) == "Y"){
		mailout($to, $subject, $message);
	}else{
		$headers = "From: $mailfrom" . "\r\n" .
		"Reply-To: $mailfrom";
		mail($to, $subject, $message, $headers);
		$mailsent = 1;
	}

	if($mailsent == 1){
		echo "\r\nA testmail was sent to $sendsummaryaddress \r\n";
	}else{
		echo "\r\n" . $mailerror . "\r\n";
	}
}

if($total != "" && strtoupper($sendsummary) == "Y"){
	if($type == "mail"){
		$subtype = " e-mail";
	}elseif($type == "ftp"){
		$subtype = " ftp";
	}else{
		$subtype = "";
	}
	$to	 = $sendsummaryaddress;
	$subject = "List of changed$subtype users and passwords";
	if($total_err == ""){
		$message = $total;
	}else{
		$message = $total . "\r\n\r\n" . $total_err;
	}

	if(strtoupper($usesmtp) == "Y"){
		mailout($to, $subject, $message);
	}else{
		$headers = "From: $mailfrom" . "\r\n" .
		"Reply-To: $mailfrom";
		mail($to, $subject, $message, $headers);
		$mailsent = 1;
	}

	if($mailsent == 1){
		echo "\r\n\r\nA mail containing a list of changed passwords was sent to $sendsummaryaddress \r\n";
	}else{
		echo "\r\n\r\n" . $mailerror . "\r\n";
	}
}

if($total != "" && $t >= 1 && strtoupper($sendinfosummary) == "Y"){
	if($type == "mail"){
		$subtype = " e-mail";
	}elseif($type == "ftp"){
		$subtype = " ftp";
	}else{
		$subtype = "";
	}
	if($total_err == ""){
		$message = $total;
	}else{
		$message = $total . "\r\n\r\n" . $total_err;
	}


	if($type == "mail"){
		$subtype = " e-mail";
	}elseif($type == "ftp"){
		$subtype = " ftp";
	}else{
		$subtype = "";
	}
	$to	 = $sendsummaryaddress;
	$subject = "List of$subtype users";
	if($total_err == ""){
		$message = $total;
	}else{
		$message = $total . "\r\n\r\n" . $total_err;
	}

	if(strtoupper($usesmtp) == "Y"){
		mailout($to, $subject, $message);
	}else{
		$headers = "From: $mailfrom" . "\r\n" .
		"Reply-To: $mailfrom";
		mail($to, $subject, $message, $headers);
		$mailsent = 1;
	}

	if($mailsent == 1){
		echo "\r\n\r\nA mail containing an $type account listing was sent to $sendsummaryaddress \r\n";
	}else{
		echo "\r\n" . $mailerror . "\r\n";
	}

}

exit(0);
?>
