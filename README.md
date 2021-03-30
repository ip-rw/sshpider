Some nice ideas here at least, going to actually rewrite this and do it properly because it's actually a cool litte
concept that I want to see working!

The idea if to rummage through a linux box in order to find credentials/keys/targets in spread to other machines via
SSH. Potentially could look at other ways to spread but for now SSH is the focus with the emphasis being on keys, not
passwords. There are far too many tools to spray common passwords at SSH servers but nothing to an effective job of
harvesting credentials and crawling systematically through intelligently gleaned targets.

* Targets:
    * Neighbouring IPs. Would be good use WHOIS to find the prefix size and to scan everything in the network.
    * Check netstat and look at ESTABLISHED connections.
    * Looking for ssh/scp/rsync commands from text files. .bash_history etc.
    * Finding, parsing and cracking 'known hosts' files. Test all IPs in ranges close to ones found already, it's
      reasonably quick algorithm but is salted (or we'd have rainbow tables and it really would be easy)
* Credentials:
    * SSH keys. Attempt to crack encrypted ones.
    * Putty PPK format.
    * Attempt to recover passwords by cracking /etc/shadow (if accessible), these along with the users and keys will be
      added to shared credentials list.

Being comprehensive is important, but vendor directories are always full of stuff we don't want. This will hopefully be
resolved by a proper design.

One other hair brained scheme would be to generate a recursive dir listing of filenames and sizes, and then hashing
these. This would mean that if we have a directory that contained nothing of any value whatsoever but was present in
lots of places, or on lots of machines, we would only have to check this once. (Is this hair brained, or is it in fact
genius?)

Most of this functionality is in this existing mess, it just need liberating and then probably rewriting from scratch...
