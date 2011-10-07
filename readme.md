# paramikojs

## About

`paramikojs` is a javascript port of [paramiko](http://www.lag.net/paramiko/).  It powers the [fireftp](https://github.com/mimecuvalo/fireftp) and [firessh](https://github.com/mimecuvalo/firessh) projects.  However, some caution should be taken if reusing the code as not all code paths have been tested (in python, yes, but not in the translated javascript).  So, coder beware!

## Getting Started

`paramikojs` doesn't work out of the box. You should check out the [fireftp](https://github.com/mimecuvalo/fireftp) or [firessh](https://github.com/mimecuvalo/firessh) projects for working examples on how to get something working.  In particular, look at [ssh2.js](https://github.com/mimecuvalo/fireftp/blob/master/src/content/js/connection/ssh2.js) as a basic start to see how it glues together.

## Note!

Before you ask, **no** this doesn't work on regular web pages.  Being able to make an SSH connection only works currently in the context of a Firefox add-on which gives provides extra libraries/permissions (i.e. ahem, sockets)
