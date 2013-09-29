'''
        .1111...          | Title: ophcrack
    .10000000000011.   .. | Author: Oliver Morton
 .00              000...  | Email: grimhacker@grimhacker.com
1                  01..   | Description:
                    ..    | runs ophcrack as a subprocess, parsing stdout.
                   ..     | does not return cracked hashes - ophcrack must
GrimHacker        ..      | output to a file which can then be parsed (otherwise
                 ..       | we can't be sure the plain is correct)
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
import re

from lib.command import Command


class Ophcrack(threading.Thread, Command):
    def __init__(self, ophcrack):
        threading.Thread.__init__(self)
        self.log = logging.getLogger(__name__)
        self.options = ophcrack
        self.nt_hash_pattern = re.compile("NT hash")

    def _stdout(self, line):  # overriding inherited function. (woo! inheritance!)
        """
        filter stdout of ophcrack - only log cracked ntlm hashes
        note this is only for running output - too many possibilities for error to use reliably for final output.
        """
        #self.log.debug(line)
        line_split = line.split(";")
        # if we don't split(;) above then it doesn't output correctly - think this is because ophcrack is rewriting the screen and using \r or it might be because the ";" is being interpreted by something.
        # passwords with ";" in them are going to break this. - doesn't matter too much as only used for running status messages
        # TODO: use a regex instead. Something like "Found password .* for" and parse it out based on the match location.
        # #this would also allow getting the status of ophcrack out.
        if len(line_split) == 2:
            # this should be output like this:
            # 0h  0m  8s; Found password t3rm1nat10n for user server-admin (NT hash #3)
            #TODO: add error handling around this
            found = line.split(";")[1].strip()  # going to have a problem if there is a ; in the username or password... #TODO: find out what is interpreting this data as commands and kill it with fire.
            #self.log.debug(found)
            if self.nt_hash_pattern.search(found):  # if the line from stdout contains the pattern it is something we want to log, otherwise ignore it.
                cracked = {'username': '', 'ntlm': '', 'nthashnum': '', 'passwd': ''}  # initialised empty to prevent key errors. ntlm included incase decide to move to separate function shared with hashcat.
                # lots of logic here to deal with spaces in usernames and passwords (hopefully ophcrack and hashcat deal with them as well or all this is pointless!)
                if found.startswith("Found empty password for user"):
                    # "Found empty password for user <username> (NT hash #<hashnumber>)"
                    username = ""
                    for i in range(5, len(found.split("(")[0].split(" "))):
                        username += "{0}".format(found.split("(")[0].split(" ")[i])
                        if i == len(found.split("(")[0].split(" ")):  # if this is the last part of the username do nothing, otherwise add a space to the username
                            pass
                        else:
                            username += " "
                    cracked['username'] = username
                    cracked['nthashnum'] = found.split("#")[-1].split(")")[0]

                elif found.startswith("Found empty password for NT hash"):
                    # "Found empty password for NT hash #<hashnumber>")
                    cracked['nthashnum'] = found.split("#")[-1]

                elif found.startswith("Found password"):
                    # Found password ThdLrFv4uu for NT hash #19712
                    # Found password s3cretpassword for user adminuser (NT hash #0)
                    if "for user" in found:
                        # parse out the password
                        # know the start of the password is always the 3rd element.
                        # find the end of the password by looking for the string "for user"
                        # use these indicies to pull out the password - by doing it like this we can handle passwords with spaces in.
                        for i in range(0, len(found.split(" ")) - 1):
                            test = ' '.join(found.split(" ")[i:i + 2])  # select two elements at a time and join together with a space in between
                            if test == "for user":
                                    endpass = i  # first element of the list AFTER the password
                                    break
                        cracked['passwd'] = ' '.join(found.split(" ")[2:endpass])
                        # parse out the username
                        username = found.split("(")[0].strip(" ").split(" ")[endpass + 2:][0]  # this is pulling out the username based on the end of the password discovered before and the "(" character because we are doing it like this we can handle usernames with spaces in.
                        cracked['username'] = username
                        # parse out the hash number
                        cracked['nthashnum'] = found.split("#")[-1].split(")")[0]
                    elif "for NT hash" in found:
                        # parse out the hash number
                        cracked['nthashnum'] = found.split("#")[-1]
                        # parse out the password
                        # know the start is always the 3rd element
                        # find the end of the password by looking for the string "for NT"
                        # use these indicies to pull out the password - doing it like this supports passwords with spaces.
                        for i in range(0, len(found.split(" ")) - 1):
                            test = ' '.join(found.split(" ")[i:i + 2])  # select two elements at a time and join together with a space in between
                            if test == "for NT":
                                    endpass = i  # first element of the list AFTER the password
                                    break
                        cracked['passwd'] = ' '.join(found.split(" ")[2:endpass])
                    else:
                        self.log.warning("can't parse ophcrack stdout. this should not affect the output file.")

                    self.log.info("OPHCRACK Found- {username}:::{passwd} from NT hash #{nthashnum}".format(**cracked))
                else:
                    # not a message about a cracked ntlm hash
                    pass
                    """
        elif len(line_split) == 5:
            # messages like:
            # 0h  0m  9s; brute force (36%); search (5%); tables: total 20, done 0, using 9; pwd found 2/5.
            # 
            success = True
            oph_status = {}
            self.log.debug("line_split = {0}".format(line_split))
            for section in line_split[1:]:  # skipping the first element - which should be the running time.
                info = section.strip()
                self.log.debug("info = {0}".format(info))
                if info.startswith("brute force"):
                    # this should be:
                    # brute force (36%)
                    try:
                        oph_status['brute'] = info.split("(")[1].split(")")[0]
                    except Exception as e:
                        self.log.warning("error parsing ophcrack message")
                        success = False
                        break
                elif info.startswith("preload"):
                    try:
                        oph_status['preload'] = info.split("(")[1].split(")")[0]
                    except Exception as e:
                        self.log.warning("error parsing ophcrack message")
                        success = False
                        break
                elif info.startswith("search"):
                    # this should be:
                    # search (5%)
                    try:
                        oph_status['search'] = info.split("(")[1].split(")")[0]
                    except Exception as e:
                        self.log.warning("error parsing ophcrack message")
                        success = False
                        break
                elif info.startswith("tables"):
                    # this should be:
                    # tables: total 20, done 0, using 9
                    tbl = info.split(" ")
                    try:
                        oph_status['tbl_total'] = tbl[2].strip(",")
                    except Exception as e:
                        self.log.warning("error parsing ophcrack message")
                        success = False
                        break
                    else:
                        try:
                            oph_status['tbl_done'] = tbl[4].strip(",")
                        except Exception as e:
                            self.log.warning("error parsing ophcrack message")
                            success = False
                            break
                        else:
                            try:
                                oph_status['tbl_using'] = tbl[6]
                            except Exception as e:
                                self.log.warning("error parsing ophcrack message")
                                success = False
                                break
                elif info.startswith("pwd found"):
                    # this should be:
                    # pwd found 2/5.
                    try:
                        oph_status['pwd_found'] = info.split(" ")[2].strip(".")
                    except Exception as e:
                        self.log.warning("error parsing ophcrack message")
                        success = False
                        break
                elif info.startswith("Found password"):
                    #
                else:
                    # running time will drop into this.
                    pass

            if success:
                if "search" in oph_status.keys():
                    self.log.debug("OPHCRACK Status- found {pwd_found}, bruteforce({brute}), search({search}), tables: total {tbl_total} done {tbl_done} using {tbl_using}".format(**oph_status))
                elif "preload" in oph_status.keys():
                    self.log.debug("OPHCRACK Status- found {pwd_found}, bruteforce({brute}), preload({preload}), tables: total {tbl_total} done {tbl_done} using {tbl_using}".format(**oph_status))
                else:
                    pass
        """
        else:
            pass
            # self.log.debug("ophcrack stdout has an unexpected number of ';' on this line. - this should not affect the output file.".format(str(line_split)))
            # might be part 1 or 2 of lm, bruteforce/search percentage etc
            # don't want to clutter the output so just ignore them for now.
            # TODO: consider making this output part of a very verbose logging setting

    def _build_cmd(self, **kwargs):
        """
        build string of command to execute
        """
        # TODO: deal with spaces in paths (e.g. ophcrack maybe full path to exe which could have a space in)
        part1 = "{0}".format(kwargs.pop("exe", None))  # ophcrack exe
        part2 = ""
        for key in kwargs.keys():
            part2 += " {0} {1}".format(key, kwargs[key])  # ophcrack optional arguments
        cmd = part1 + part2
        return cmd

    def run(self):
        """
        run ophcrack subprocess
        """
        self.log.debug("starting thread: '{0}'".format(self.name))
        cmd = self._build_cmd(**self.options)
        self._execute(cmd)
        self.log.debug("finished thread: '{0}'".format(self.name))
