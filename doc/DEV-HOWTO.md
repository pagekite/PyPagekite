## HowTo for developers ##

### Getting started ###

    $ git clone https://github.com/pagekite/PyPagekite.git
    $ git clone https://github.com/pagekite/PyBreeder.git
    $ git clone https://github.com/pagekite/PySocksipyChain.git

    $ cd PyPagekite
    $ $(make dev)    # sets up the environment
    $ ./pk           # run the local code
    $ make           # run tests, build distributable "binary"

### Exploring the code ###

PageKite has is still being refactored from its original form as one big
giant Python script.

The code mostly lives in the `pagekite/` directory and its subdirectories.
Some utilities and custom applications built on top of PageKite live in
`scripts/`, and documentation is in `doc/`.

