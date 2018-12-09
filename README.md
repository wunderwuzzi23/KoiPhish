# KoiPhish - the phishing proxy

A proxy to run effective phishing sites for adverserial emulation.

KoiPhish is a phishing proxy. It relays all requests a user makes to the KoiPish to the actual target and responses are sent back to the end user. On the way in and out common links are overwritten in order to not break the user experience and functionality. The benefit of this approach compared to cloning a website is that it will have the same look and feel as the target.

Why is this useful?
Most web sites these days support multi factor authentication. KoiPish can be leveraged to seemlessly intergrate in the multi step flow,  continously relaying requests back and forth, and ultimatley gain access to a users session token.


                                                       Keep Relaying 
End User     +-------------------->    KoiPhish    +-------------------->    Actual Login Page
                                                   <--------------------+     and MFA Provider
                  Keep Relaying
             +--------------------> 
             <--------------------+                           
                                              

This keeps going until the final session token is grabbed by KoiPhish.

Adjustments
The code is very basic at this point. For a specific pen test scenarios most likely adjustments need to be made to request flow and query paths, etc. Over time more relay capabilites could be added.

Notice
Of course, only every leverage this when authorized by appropriate stakeholders. You are responsible for your own actions.
