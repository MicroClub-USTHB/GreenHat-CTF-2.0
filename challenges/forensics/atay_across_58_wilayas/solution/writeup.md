# The Algerian Tea Merchant 🍃

**Category**: Forensics
**Difficulty**: Medium 

## Story
A tea merchant has been caught selling large quantities of tea. Could he be hiding something? # Description of the challenge

We've captured some of their network traffic. Can you find what they're really planning?

**File**: `algerian_tea_challenge.pcap`

**Flag format**: ghctf{...}

## Solution

The challenge suggest that the merchant is sending tea to communicate somehow a message.
With the challenge heavily insisting on the number 58 and the 58 wilayas of algeria we can guess there is something to do with that.
Not to be confused with other requests targeting other places not algerian wilayas, those are to be ignored and removed because they even contain a fake flag.

After securing all the requests of the algerian wilayas we can strip the json to extract only the number of the wilaya, and using base58 to construct our flag after parsing each number to the correct base58 caracter:
10 -> A
11 -> B
.
.
.
58 -> z

and then using a tool like CYberChef to get the flag: **ghctf{4t4y_t0_th3_d34th}**
