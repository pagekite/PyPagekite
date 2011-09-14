# The PageKite v0.5 remote-control protocol #

PageKite 0.4 introduced a basic protocol for implementing a UI wrapper
around PageKite, where PageKite would send easily parsed information about
what was going on to stdout, and could drive the signup process as well.

PageKite 0.5 expands on this, adding the ability to change the configuration
of a running PageKite on the fly, save config changes to disk and allow remote
control over a socket.

What follows is a basic description of the the control channel.


## Basic message format ##

PageKite will send messages looking like this:

    status_msg: Starting up...
    status_tag: startup
    notify: Hello! This is pk v0.4.99pre5-1.
    status_msg: Collecting entropy for a secure secret...
    ...
    status_msg: Kites are flying and all is well.
    status_tag: flying
    ...
    be_status: status=1000 domain=foo.pagekite.me port= proto=http ...
    be_path: url=http://foo.pagekite.me/ policy=default src=/path/to/file
    ...
    notify: Some random text message

These messages will continue to arrive every few seconds for the lifetime
of the program, updating the UI on the current state.

Each message will span exactly one line (`\n` terminated), and is split into
the name and argument separated by `: ` (semicolon, space).


### Existing status tags ###

Status tags are meant to be used to update an indicator icon.  The following
tags currently exist:

    startup  -  The program is starting up
    connect  -  Connecting to a front-end
    dyndns   -  Updating dynamic DNS
    traffic  -  A nontrivial amount of bytes are being transferred
    serving  -  An HTTP request is being handled
    idle     -  Running as front-end, waiting for back-ends.
    down     -  Running as back-end, waiting for a front-end.
    flying   -  Flying some kites!
    exiting  -  Shutting down

## Run-time control commands ##

The UI can control the pagekite process by sending commands in the same
format as basic messages: `command: argument\n`

The following commands are recognized:

    exit: reason       # Quit the program
    restart: reason    # Shut down all tunnels and restart
    config: var=value  # Parse one line of configuration
    addkite: kitename  # Add a new kite (triggers wizard)
    save: reason       # Save the running config to disk

Reasons are currently ignored, but will be written to the log to help with
debugging.

Configuration commands of particular interest to UI programmers are:

    webpath=<HOST/PORT>:<WEBPATH>:<POLICY>:<FILEPATH>
    nowebpath=<HOST/PORT>:<WEBPATH>

These can be used to register/deregister paths with the built-in HTTPD on
the fly during program runtime.


## Interaction message format ##

When PageKite enters its signup or kite creation phase, it will send requests
to the UI for user input.

The UI must implement the following actions:

    ask_yesno
    ask_email
    ask_kitename
    ask_multiplechoice
    tell_message
    tell_error

An optional additional pair of UI hints are `start_wizard` and `end_wizard`
which group together a related sequence of questions and answers.  Note that
`start_wizard` may be sent repeatedly during the same session, to update the
subject of the current conversation.

A typical session might look like so:

    $ pagekite.py --remoteui --friendly  # add --clean to simulate first use

    start_wizard: Create your first kite!
    begin_ask_yesno
     default: True
     question: Use the PageKite.net service?
     expect: yesno
    end_ask_yesno

Reply: `y`

    begin_ask_email
     question: What is your e-mail address?
     expect: email
    end_ask_email

Reply: `person@example.com`

    begin_ask_kitename
     domain: .pagekite.me
     question: Name your kite:
     expect: kitename
    end_ask_kitename

Reply: `person.pagekite.me`

    start_wizard: Creating kite: person.pagekite.me
     begin_ask_multiplechoice
     preamble: Do you accept the license and terms of service?
     choice_1: Yes, I agree!
     choice_2: View Software License (AGPLv3).
     choice_3: View PageKite.net Terms of Service.
     choice_4: No, I do not accept these terms.
     default: 1
     question: Your choice:
     expect: choice_index
    end_ask_multiplechoice

Reply: `1`

    tell_message: Your kite, person.pagekite.me, is live! ...
    end_wizard: done
    begin_ask_yesno
     default: True
     question: Save settings to /home/bre/.pagekite.rc?
     expect: yesno
    end_ask_yesno

Reply: `y`

    status_msg: Starting up...
    status_tag: startup
    notify: Hello! This is pk v0.4.99pre5-1.
    ...

Implementations should accept unknown arguments/commands gracefully by
ignoring them, or in the case of unknown commands, immediately replying
with the default value if present.

Note that control commands won't work while PageKite is waiting for a
reply to a UI request.

