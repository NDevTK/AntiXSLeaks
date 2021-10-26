# AntiXSLeaks
A extension to prevent XS-Leaks,  
Sets secure default headers and more! (https://w3c.github.io/webappsec-post-spectre-webdev/)

- Dont allow cross origin to access the window reference,  
as this can leak the window length and navigation timings.
- Make iframe embeds opt in,  
Prevents click jacking.
- Block cross origin Initiator if its a protected origin (User must directly vist the origin),  
Stops XS-Search attacks and URL based refected XSS.
- Block hash navigations

## Known issues
If a protected origin redirects to a URL based XSS on the same-origin it will be allowed.

## Improvements
Add SameSite cookie support.
