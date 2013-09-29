'''
        .1111...          | Title: hashcat
    .10000000000011.   .. | Author: Oliver Morton
 .00              000...  | Email: grimhacker@grimhacker.com
1                  01..   | Description:
                    ..    | runs hashcat as a subprocess, parsing stdout and
                   ..     | writing a pot file for use in case of crash.
GrimHacker        ..      | returns a list of dictionaries (cracked hashes)
                 ..       | using a queue.
grimhacker.com  ..        |
@_grimhacker   ..         |
--------------------------------------------------------------------------------
Created on 22 Sep 2013
@author: GrimHacker
Copyright (c) 2013 GrimHacker
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
'''

import logging
import threading
import Queue
import re

from lib.command import Command


class Hashcat(threading.Thread, Command):
    def __init__(self, hashcat, return_queue, pot_file="hcpot.txt"):
        threading.Thread.__init__(self)
        self.log = logging.getLogger(__name__)
        self.options = hashcat
        self.hash_re = re.compile("[A-Z0-9]{32}:", re.IGNORECASE)  # regular expression for 32 character alphanumeric string followed by semicolon
        self.cracked = []
        self.return_queue = return_queue

        self.pot = Queue.Queue()  # can call self.pot.put(hash) which seems fairly sensible/logical/easy to read
        self.pot_thread = self._Pot(self.pot, pot_file)
        self.pot_thread.start()

    class _Pot(threading.Thread):
        def __init__(self, queue, pot_file):
            threading.Thread.__init__(self)
            self.log = logging.getLogger(__name__)
            self.queue = queue
            self.pot = pot_file
            #self.log.debug("pot thread initialised")

        def _update_pot(self, hash_):
            """
            add hash to a file if not already in it.
            returns True is the hash is in the pot (either because it is a duplicate or it has been successfully added).
            returns False if there was a problem writing to the pot.
            """
            self.log.debug("updating hashcat pot file '{0}'".format(self.pot))
            try:
                with open(self.pot, 'r') as f:
                    if "{0}\n".format(hash_) not in f:  # added \n to the end of the plain so can match the full line in the file without doing any stripping.
                        self.log.debug("plain not in pot")
                    else:
                        return True  # indicates that the hash is in the pot.
            except IOError as e:
                self.log.warning("couldn't open pot, creating it and assuming all plains are new.")
                try:
                    with open(self.pot, 'w') as h:
                        try:
                            h.writelines("{0}\n".format(hash_))
                        except Exception as e:
                            self.log.warning("failed to write: {0}".format(hash_))
                        return True  # indicates the hash is in the pot (we did write successfully)
                except IOError as e:
                    self.log.warning("couldn't open pot' to write: {0}".format(hash_))
            else:
                # if there was no problem reading from the file - i.e. it exists. append to the file
                self.log.debug("appending new plains to file")
                try:
                    with open(self.pot, 'a') as j:
                        try:
                            j.writelines("{0}\n".format(hash_))
                        except Exception as e:
                            self.log.warning("failed to append '{0}' to pot".format(hash_))
                except IOError as e:
                    self.log.warning("failed to append plains to pot")  # should be that the file doesn't exist
                    self.log.warning("{0}: {1}".format(e.errno, e.strerror))
                else:
                    return True  # indicates the hash is in the pot (we did write successfully)
            # the exception blocks for failure fall to here.
            return False  # indicates we didn't write successfully

        def run(self):
            """
            create a pot of cracked hashes as they are discovered - just in case.
            """
            #self.log.debug("pot thread run function")
            while True:  # exiting is handled by passing False in the queue.
                #self.log.debug("pot thread is looping")
                cracked = self.queue.get()
                if cracked == False:  # could do "if not cracked" but i don't think its as readable.
                    return  # received the exit flag (False).
                else:
                    #try:
                    self._update_pot("{hash}:{passwd}".format(**cracked))  # wasn't the exit flag so assume its a hash.
                    #except Exception as e:
                    #    self.log.warning("invalid entry to hashcat pot")  # something invalid in the queue.
                    #    self.log.warning("{0}: {1}".format(e.errno, e.strerror))

    def _stdout(self, out):  # overriding inherited function. (woo! inheritance!)
        """
        filter output of hashcat. only log cracked hashes and warnings
        """
        # TODO: might be better parsing .restore file...
        for line in out.split("\n"):
            if line != "":
                self.log.debug(line)
                if line.startswith("Cannot convert"):
                    self.log.warning("HASHCAT- {0}".format(line))
                elif self.hash_re.search(line):
                    # TODO: having problems here. not getting the cracked password until the status message is refreshed (by pressing 's').
                    # DONE: _build_cmd() adds --status flag. this auto scrolls the status message so we get the output we want.
                    cracked = {}
                    match = self.hash_re.search(line)  # match is now a regular expression object (or None if no match - put that shouldn't happen because of the elif that got us here.)
                    start, end = match.regs[0]  # this is the start (inclusive) and end (exclusive) positions of the match
                    # self.log.debug("match start {0} match end {1}".format(start, end))
                    output = line[start:]  # the cracked password is not included in the regular expression match so need to get to the end of the line. (password is the last thing on the line in the hashcat output.)
                    outsplit = output.split(":")
                    # cracked = {'ntlm': outsplit[0], 'passwd': outsplit[1]}
                    cracked['hash'] = outsplit[0]
                    cracked['passwd'] = outsplit[1]
                    # self.log.debug("cracked: {}".format(cracked))
                    self.log.info("HASHCAT Found- {hash}:{passwd}".format(**cracked))
                    self.cracked.append(cracked)
                    #self.log.debug("sending to pot")
                    self.pot.put(cracked)  # send cracked hash to be added to the pot
                    #self.log.debug("sent to pot")
                else:
                    # status messages etc.
                    # add to very verbose logging option?
                    pass

    def _build_cmd(self, **kwargs):
        """
        build string of command to execute
        #TODO: deal with spaces in paths (e.g. hashcat maybe full path to exe which could have a space in)
        """
        # The order is important here. Have to pop off the positional arguments before doing the optional ones.
        start = "{0} --status".format(kwargs.pop("exe", None))  # hashcat exe and status option (auto scrolls status)
        end = " {0}".format(kwargs.pop("hashfile", None))
        wordlists = kwargs.pop("wordlists", None)
        for list_ in wordlists:
            end += " {0}".format(list_)

        mid = ""
        for key in kwargs.keys():
            if key == "-r":
                for file_ in kwargs[key]:
                    mid += " {0} {1}".format(key, file_)
            else:
                mid += " {0} {1}".format(key, kwargs[key])  # hashcat optional arguments

        cmd = start + mid + end
        self.log.debug("cmd is: '{0}'".format(cmd))
        return cmd

    def run(self):
        """
        run hashcat subprocess
        """
        self.log.debug("starting thread: '{0}'".format(self.name))
        cmd = self._build_cmd(**self.options)
        self._execute(cmd)
        self.return_queue.put(self.cracked)
        self.log.debug("sending kill message to pot thread")
        self.pot.put(False)
        self.log.debug("waiting for pot thread to exit")
        self.pot_thread.join()  # this should be pretty much immediate. only cause of delay that i foresee is if the thread has a backlog of hashes to write to the pot.
        self.log.debug("finished thread: '{0}'".format(self.name))
