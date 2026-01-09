# Handles pihole blocklists to improve performance in pihole
The script merges the blocklists given in the sources.txt file into one large list. 
Additionally you may define allowed domains and additional blocked domains in the files allow.txt and block.txt to avoid having rules within pihole.
Adjust the output path as required and then you can import the newly merged blocklist from the target url. 
Of course you may combine the local rules and additional blocklists as you wish. 
## Why
This should centralize the lists for my pihole instances and improve performance. It will also remove duplication and deactivate non working block lists
after 5 successive failures. The log output will tell you about the details. 

Enjoy.
