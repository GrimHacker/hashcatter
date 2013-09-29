'''
        .1111...          | Title: command
    .10000000000011.   .. | Author: Oliver Morton
 .00              000...  | Email: grimhacker@grimhacker.com
1                  01..   | Description:
                    ..    | executes a command as a subprocess
                   ..     |
GrimHacker        ..      |
                 ..       |
grimhacker.com  ..        |
@_grimhacker   ..         |
--------------------------------------------------------------------------------
Created on 22 Sep 2013
@author: GrimHacker
'''

import logging

from subprocess import CalledProcessError
from lib.async_subprocess import AsyncPopen, PIPE


class Command():
    def __init__(self):
        self.log = logging.getLogger(__name__)

    def _stdout(self, out):
        """
        print line from stdout of executed command
        """
        for line in out.split("\n"):
            if line != "":  # output anything that isn't a blank line
                self.log.info("{0}".format(line))

    def _stderr(self, err):
        """
        print line from stderr of executed command
        """
        for line in err.split("\n"):
            if line != "":  # output anything that isn't a blank line
                self.log.warning("{0}".format(line))

    def _execute(self, cmd):
        """
        run the specified command as a subprocess
        """
        self.log.debug("running: '{0}'".format(cmd))
        try:
            proc = AsyncPopen(cmd, stdout=PIPE, stderr=PIPE)
            while proc.poll() is None:  # while subprocess hasn't finished
                out, err = proc.communicate("s")
                if err is not None:
                    self._stderr(err)
                if out is not None:
                    self._stdout(out)
                #line = proc.stdout.readline().strip("\n")
                #self._stdout(line)
                # line = proc.stderr.readline().strip("\n")  # waits for stderr. #TODO: need to put this in a thread
                # self._stderr(line)
            # when we get to here the subprocess has finished running
        except CalledProcessError, e:
            self.log.error("{0}: {1}".format(e.errno, e.strerror))
            #return "{0}: {1}".format(e.errno, e.strerror)