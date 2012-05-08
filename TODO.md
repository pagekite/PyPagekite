# TODOS #

## Known bugs ##

   * XML-RPC CNAME creation fail
   * SSL verification fail
   * Signup message weirdness
   * Poor handling of reconfiguration


## General ##

   * 0.4.7/launch: COMPLETE DOCUMENTATION. Bugfixes.

   * 0.5.x: Add UI to report available upgrades at the back-end.
   * 0.5.x: Windows: Auto upgrades?


## Built-in HTTPD ##

   * 0.5: Allow uploading, somehow
   * 0.5: Allow access controls based on OpenID/Twitter/Facebook ?
   * 0.5: Create javascript for making directory listings prettier
     * Add basic photo albums
     * Add feature to thumbnail/preview/re-encode images/audio/video


## Packaging ##

   * 0.5: Create Windows distribution
   * 0.5: Create Windows .msi

   * 0.6: Package lapcat
   * 0.6: Create Mac OS X GUI and package: Talk to Sveinbjörn?


## Code cleanup ##

   * Files are still too big, github chokes
   * Function naming is inconsistent
   * Need docstrings all over pagekite source
   * Unneeded ( ) in a few places
   * Bad form: if this: thenfoo

### Optimization ###

   * Add QoS and bandwidth shaping
   * Add a scheduler for deferred/periodic processing
   * Replace string concatenation ops with lists of buffers

### Protocols ###

   * Make tunnel creation more stubborn, try multiple ports, etc.
   * Add XMPP and incoming SMTP support
   * Replace/augment current tunnel auth with SSL certificates


