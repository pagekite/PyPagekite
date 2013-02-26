# TODOS #

## Known bugs ##

   * PageKite frontends will disconnect tunnels when kites run out of quota.
     This will hurt Kazz.am, should recheck all kites and only disable out of
     quota ones, disconnecting only when all run out.  Also, UI issues.

   * XML-RPC CNAME creation fail
   * Signup message weirdness
   * Poor handling of reconfiguration
   * Poor handling of FD exhaustion
   * Kite creation can be confusing if a name is already taken.

   * WONTFIX: SSL verification fail - unfixable with pyOpenSSL :-(


## Code cleanup ##

   * Files are still too big, github chokes
   * Function naming is inconsistent
   * Need docstrings all over pagekite source
   * Unneeded ( ) in a few places
   * Bad form: if this: thenfoo


## General ##

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


### Optimization ###

   * Add QoS and bandwidth shaping
   * Add a scheduler for deferred/periodic processing
   * Replace string concatenation ops with lists of buffers

### Protocols ###

   * Make tunnel creation more stubborn, try multiple ports, etc.
   * Add XMPP and incoming SMTP support
   * Replace/augment current tunnel auth with SSL certificates


### Better kite registration ###

   1. Quota calculations should be done on a kite-by-kite basis:
      - kites out of quota get disabled
      - tunnels only die if they have *no* live/challenged kites left

   3. Stop requiring the reconnect after a challenge, just establish
      a tunnel with zero kites?

   2. Registration
      - recognize the challenge/response headers within chunk headers,
        so kite can be set up using NOOP chunks.
      - add a back-end initiated "remove this kite" message


### Dynamic DNS ###

Dynamic DNS updates are the only SPoF left in the PageKite.net service,
should fix by:

   * Modify pagekite.py to update multiple (all) update servers


### Lame-duck ###

Lame-duck mode is when a front-end knows it can no longer handle traffic
but still has established user connections.  The goal is to shut down as
quickly as possible, without dropping (too much) traffic.

   * Trigger on: normal shutdown, out of FDs, OOM, uncaught exceptions
   * Add signaling to tunnels to warn that FE is lame.
   * Shut down all listening sockets and daemonize so new FE can start up
   * Implement protocol for sending entire live tunnel to new FE process?
   * Give existing conns 60 seconds to finish?
   * Add "lame" recognition in back-end (also "rejected")


