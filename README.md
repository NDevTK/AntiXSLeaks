# AntiXSLeaks
A extension to prevent XS-Leaks,  
Sets secure default headers.

- Dont allow cross origin to access the window reference,  
as this can leak the window length and navigation timings.
- Make iframe embeds opt in.
- Block cross origin Initiator if its a protected origin.
