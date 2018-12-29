# KoiPhish - The Phishing Proxy

KoiPhish is a simple yet beautiful phishing proxy idea. It relays requests a client makes to the KoiPish to the actual target and responses are sent back to the client. On the way in and out common links are overwritten in order to not break the user experience and functionality. The benefit of this approach compared to cloning a website is that it will have the same look and feel as the target, and automatically adjust to changes down the road. The code is very basic at this point. I'm using it to learn Golang. 

## Why is this useful?
Most web sites these days support multi factor authentication. KoiPish can integreate in the multi step flow,  continuously relaying requests back and forth, and eventually gain access to a user's session token.

## Illustration

                                                             Keep Relaying                               
      End User     +-------------------->    KoiPhish    +-------------------->    Actual Login Page
                                                         <--------------------+    
                       Keep Relaying      
                   +-------------------->                +-------------------->     and MFA Provider
                   <--------------------+                <--------------------+           
             
This keeps going until the passwords and/or session tokens (after 2FA) are grabbed by KoiPhish.


## Adjustments

For actual pentesting more adjustments need to be made, like configuring target, etc. The code is not "point and click".


## Mitigation

Leverage security keys and U2F to help mitigate phishing attacks. Learn more here:
https://fidoalliance.org/fido2/
https://en.wikipedia.org/wiki/WebAuthn


## Disclaimer

Pentesting requires authorization and consent by appropriate stakeholders. Do not do illegal things. You are responsible for your own actions.

