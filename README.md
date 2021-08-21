# AntiXSLeaks
A extension to prevent XS-Leaks,  
Sets secure default headers and more! 

- Dont allow cross origin to access the window reference,  
as this can leak the window length and navigation timings.
- Make iframe embeds opt in,  
Prevents click jacking.
- Block cross origin Initiator if its a protected origin (User must directly vist the origin),  
Stops XS-Search attacks and URL based refected XSS.
