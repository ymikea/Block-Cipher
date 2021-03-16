# WSU-CRYPT

## Files
- wsu-crypt.c
- key.txt
- plaintext.txt
- Makefile
- README.md

## Compile Steps



## Run Instructions
./wsu-crypt -e -k key.txt -in plaintext.txt -out ciphertext.txt         (encryption)
./wsu-crypt -d -k key.txt -in ciphertext.txt -out decrypted.txt         (decryption)


## Author
### 👤 Yekaalo Habtemichael
* Github: [@ymikea](https://github.com/ymikea)
* Website: [RSLI](https://www.rsltrader.com)



## Implementation
The Application utilizes NodeJS, MongoDB, Bootstrap, and Jquery. The App is using express for the server. Bcrypt and Passport for local and Google login authentications. To keep track of users it's using sessions to make sure the validity of the authentication and if a user is still logged in/out.

The app can be used from a Desktop or Mobile. Supports mobile and desktop versions. The constraints should be able to maintain in all sizes without falling apart while resizing on the browser.

Deployment of the app is handled by AWS. It is running in an EC2 instance in port 3000. The domain has a secured connection with HTTPS. AWS load balancer will handle securing the connection and redirecting HTTP to secure connection.    

## License
[MIT](https://choosealicense.com/licenses/mit/) &copy; 2020 [Yekaalo Habtemichael](#) 
