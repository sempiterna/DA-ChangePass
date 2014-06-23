DA-ChangePass
=============

A small PHP commandline script to change passwords for DA users, or e-mail addresses, or FTP accounts. This script can reset either all accounts, or a single domain, or a single (DA/e-mail/ftp) user.

This script will attempt to download the following required file if it is not found in the same directory. But you can [manually download](http://files.directadmin.com/services/all/httpsocket/httpsocket.php) it as well.

If `$usesmtp` is set to `Y`, the [PHPmailer](https://github.com/PHPMailer/PHPMailer) package is required.

Make sure all options are checked and, where needed, updated. All options have a short explanation behind it that explains its function. Once done, set `$scriptedited` to `Y`.

This script can be executed locally on a DirectAdmin server, but can also connect to (any) DirectAdmin server from a remote location. This is useful if you manage many DirectAdmin servers.

## Usage:

### Change the password of one user:
`./da_changepass.php --user <username> [optional password]`

If no password is given, a random one will be generated

### Change the passwords for all users except the admin user:
`./da_changepass.php --alluser`

### Change the e-mail password for all e-mail accounts on the server:
`./da_changepass.php --allmail`

### Change all e-mail passwords for a specific domain:
`./da_changepass.php --mail <domainname>`

### Change the e-mail password for a specific e-mail address:
`./da_changepass.php --mail <e-mail address> [optional password]`

If no password is given, a random one will be generated

### Change the ftp account password for all ftp accounts on the server:
`./da_changepass.php --allftp`

### Change all ftp account passwords for a specific domain:
`./da_changepass.php --ftp <domainname>`

### Change the ftp account password for a specific account:
`./da_changepass.php --ftp <ftpuser@domain> [optional password]`

If no password is given, a random one will be generated

### Display a list of ftp or e-mail accounts:
`./da_changepass.php --list <ftp | mail> [optional domain]`

### Send a test e-mail:
`./da_changepass.php --mailtest`
