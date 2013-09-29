'''
        .1111...          | Title: parsehashes
    .10000000000011.   .. | Author: Oliver Morton
 .00              000...  | Email: grimhacker@grimhacker.com
1                  01..   | Description:
                    ..    | parses hashes from and to files
                   ..     |
GrimHacker        ..      |
                 ..       |
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
import re

from datetime import datetime


class ParseHashes():
    def __init__(self):
        self.log = logging.getLogger(__name__)

    def _blanks(self, hashes):
        """
        splits hashes for blank and not blank passwords into separate lists
        returns not_blank, blank
        """
        blank = []
        not_blank = []
        for hash_ in hashes:
            if hash_['ntlm'].upper() == "31D6CFE0D16AE931B73C59D7E0C089C0":  # ntlm hash for blank password
                blank.append(hash_)
                self.log.debug("blank password for: '{0}'".format(hash_['username']))
            else:
                not_blank.append(hash_)
        self.log.debug("found {0} blank passwords".format(len(blank)))
        return not_blank, blank

    def separate_lm_ntlm(self, hashes):
        """
        splits ntlm, lm and blank hashes into separate lists
        returns ntlm, lm, blank
        """
        ntlm = []
        lm = []

        hashes, blank = self._blanks(hashes)
        for hash_ in hashes:
            if hash_['lm'].upper() in ["0" * 32, "NO PASSWORD*********************", "AAD3B435B51404EEAAD3B435B51404EE", ""]:
                # LM hash is not present or is for a blank password then LM hash is not stored
                # can check against blank lm hash because already removed actual blank passwords based on ntlm hash.
                ntlm.append(hash_)
            else:
                lm.append(hash_)
        self.log.info("found {0} lm hashes, {1} ntlm hashes, {2} blank passwords".format(len(lm), len(ntlm), len(blank)))
        return ntlm, lm, blank

    def separate_cracked_uncracked(self, hashes):
        """
        split hashes into cracked and uncracked
        """
        # blank hashes
        #self.log.debug("hashes to separate: {0}".format(hashes))
        not_blank, blanks = self._blanks(hashes)
        uncracked = []
        cracked = []
        #self.log.debug("hashes to check if cracked: {0}".format(hashes))
        for hash_ in not_blank:
            if hash_['passwd'] == "":  # separated out actual blank hashes so anything with a blank string in the passwd field is an uncracked hash.
                uncracked.append(hash_)
            else:
                cracked.append(hash_)
        cracked += blanks
        return cracked, uncracked

    def remove_machine(self, hashes):
        """
        remove machine accounts
        returns a list of dictionaries of hashes with usernames that do not end with "$"
        """
        not_machine = []
        for hash_ in hashes:
            if hash_['username'].endswith("$"):
                self.log.debug("removing machine account: '{0}'".format(hash_['username']))
            else:
                not_machine.append(hash_)
        self.log.info("removed {0} machine accounts".format(len(hashes) - len(not_machine)))
        return not_machine

    def remove_disabled(self, hashes):
        """
        remove disabled accounts
        returns a list of dictionaries of hashes with usernames that do not contain "disabled"
        """
        not_disabled = []
        disabled = re.compile("disabled")
        for hash_ in hashes:
            if disabled.search(hash_['username']) is not None:
                self.log.debug("removing disabled account: '{0}'".format(hash_['username']))
            else:
                not_disabled.append(hash_)
        self.log.info("removed {0} disabled accounts".format(len(hashes) - len(not_disabled)))
        return not_disabled

    def remove_history(self, hashes):
        """
        remove history accounts
        returns a list of dictionaries of hashes with usernames that do not contain "history"
        """
        not_history = []
        history = re.compile("history")
        for hash_ in hashes:
            if history.search(hash_['username']) is not None:
                self.log.debug("removing history account: '{0}'".format(hash_['username']))
            else:
                not_history.append(hash_)
        self.log.info("removed {0} history accounts".format(len(hashes) - len(not_history)))
        return not_history

    def read_pwdump(self, hashfile):
        """
        parse pwdump file and return a list of dictionaries
        keys: username,rid,lm,ntlm,pass1,pass2,passwd
        'rid' my be domain?  #doesn't matter to this script in practice  #TODO: find out why (fgdump/pwdump?)
        """
        # TODO: handle error of file does not exist/fail to open.
        hashes = []
        with open(hashfile, 'r') as f:
            for line in f:
                try:
                    hashsplit = line.strip().split(":")
                except Exception as e:
                    self.log.warning("failed to split hash {0}".format(line))  # badly formatted hash
                    self.log.warning("{0}: {1}".format(e.errno, e.strerror))
                    # TODO: possibly username with : in it in which case should try splitting on ? but will add support for that later...
                else:
                    try:
                        hash_ = {'username': hashsplit[0], 'rid': hashsplit[1], 'lm': hashsplit[2], 'ntlm': hashsplit[3], 'pass1': hashsplit[4], 'pass2': hashsplit[5], 'passwd': hashsplit[6]}
                    except Exception as e:
                        self.log.warning("failed to create hash dictionary from: {0}".format(hashsplit))
                        #self.log.warning("{0}: {1}".format(e.errno, e.strerror)) # causes its own error because errno is not an attribute
                    else:
                        self.log.debug("hash = {0}".format(hash_))
                        hashes.append(hash_)
        return hashes

    def read_hcout(self, hcfile, format_=3):
        """
        parse hashcout output file
        return dictionary of {hash: passwd}
        """
        cracked = []

        def _read_format1(self, line):
            """
            hash[:salt]
            """
            self.log.critical("not implemented")
            exit()

        def _read_format2(self, line):
            """
            plain
            """
            self.log.critical("not implemented")
            exit()

        def _read_format3(self, line):
            """
            hash[:salt]:plain
            returns dictionary:
            keys: hash, salt, plain, hex_plain
            """
            split_line = line.strip("\n").split(":")
            if len(split_line) == 3:
                cracked = {'hash': split_line[0], 'salt': split_line[1], 'plain': split_line[2], 'hex_plain': ""}
            elif len(split_line) == 2:
                cracked = {'hash': split_line[0], 'salt': "", 'plain': split_line[2], 'hex_plain': ""}
            else:
                self.log.critical("incorrect format 'line'. should be: 'hash[:salt]:plain'")
                exit()

        def _read_format4(self, line):
            """
            hex_plain
            """
            self.log.critical("not implemented")
            exit()

        def _read_format5(self, line):
            """
            hash[:salt]:hex_plain
            """
            self.log.critical("not implemented")
            exit()

        def _read_format6(self, line):
            """
            plain:hex_plain
            """
            self.log.critical("not implemented")
            exit()

        def _read_format7(self, line):
            """
            hash[:salt]:plain:hex_plain
            """
            self.log.critical("not implemented")
            exit()

        parsers = {1: _read_format1, 2: _read_format2, 3: _read_format3, 4: _read_format4, 5: _read_format5, 6: _read_format6, 7: _read_format7}
        if format_ in parsers.keys():
            parser = parsers[format_]
        else:
            self.log.critical("invalid format_ option (should be integer between 1 and 7 inclusive)")  # Dear future self, if hitting this message and can't figure out why, i bet it is because value of format_ is a str not an int. ;)
            exit()
        with open(hcfile, 'r') as f:
            for line in f:
                crack = parser(line)
                cracked.append(crack)
                self.log.debug("read line: {0}".format(crack))
        return cracked

    def _write_file(self, hashes, filename):
        """
        write lines to a file
        returns filename
        """
        self.log.debug("writing hashes to '{0}'".format(filename))
        with open(filename, 'w') as f:
            for hash_ in hashes:
                try:
                    f.writelines("{0}\n".format(hash_))
                except Exception as e:
                    self.log.warning("failed to write hash '{0}' to file.".format(hash_))
                    self.log.warning("{0}: {1}".format(e.errno, e.strerror))
        return filename

    def write_pwdump(self, hashes, fileprefix=""):
        """
        write hashes to file in pwdump format:
        {username}:{rid}:{lm}:{ntlm}:{pass1}:{pass2}:{passwd}
        returns filename
        """
        filename = "{0}{1}.pwdump".format(fileprefix, datetime.strftime(datetime.now(), "%Y%m%d%H%M%S"))  # by default at 1300 on 01/02/2013 filename would be "20130201130000.pwdump"
        pwdump = []
        self.log.debug("creating list of hashes in pwdump file format")
        for hash_ in hashes:
            try:
                hashline = "{username}:{rid}:{lm}:{ntlm}:{pass1}:{pass2}:{passwd}".format(**hash_)
            except Exception as e:
                self.log.warning("failed to create hashline from: {0}".format(hash_))
                self.log.warning("{0}: {1}".format(e.errno, e.strerror))
            else:
                pwdump.append(hashline)
        return self._write_file(pwdump, filename)

    def write_hcntlm(self, hashes, fileprefix=""):
        """
        write hashes to file in hashcat ntlm format:
        {ntlm}
        returns filename
        """
        filename = "{0}{1}.hcntlm".format(fileprefix, datetime.strftime(datetime.now(), "%Y%m%d%H%M%S"))  # by default at 1300 on 01/02/2013 filename would be "20130201130000.hcntlm"
        hcntlm = []
        self.log.debug("creating list of ntlm hashes")
        for hash_ in hashes:
            try:
                hashline = "{ntlm}".format(**hash_)
            except Exception as e:
                self.log.warning("failed to create hashline from: {0}".format(hash_))
                self.log.warning("{0}: {1}".format(e.errno, e.strerror))
            else:
                hcntlm.append(hashline)
        return self._write_file(hcntlm, filename)

    def write_hcout(self, hashes, format_=3, fileprefix=""):
        """
        write hashes in hashcat output style
        """
        filename = "{0}{1}.hcout".format(fileprefix, datetime.strftime(datetime.now(), "%Y%m%d%H%M%S"))  # by default at 1300 on 01/02/2013 filename would be "20130201130000.hcout"

        def _write_format1(hash_):
            """
            hash[:salt]
            """
            self.log.critical("not implemented")
            exit()

        def _write_format2(hash_):
            """
            plain
            """
            self.log.critical("not implemented")
            exit()

        def _write_format3(hash_):
            """
            hash[:salt]:plain
            returns dictionary:
            keys: hash, salt, plain, hex_plain
            """
            if 'salt' in hash_.keys() and hash_['salt'] != '':  # can do it like this because if 'salt' is not in keys that half evaluates to false, so it get to the second half and therefore won't error ^_^
                line = "{ntlm}:{salt}:{passwd}".format(**hash_)
            else:
                line = "{ntlm}:{passwd}".format(**hash_)
            return line

        def _write_format4(hash_):
            """
            hex_plain
            """
            self.log.critical("not implemented")
            exit()

        def _write_format5(hash_):
            """
            hash[:salt]:hex_plain
            """
            self.log.critical("not implemented")
            exit()

        def _write_format6(hash_):
            """
            plain:hex_plain
            """
            self.log.critical("not implemented")
            exit()

        def _write_format7(hash_):
            """
            hash[:salt]:plain:hex_plain
            """
            self.log.critical("not implemented")
            exit()

        writers = {1: _write_format1, 2: _write_format2, 3: _write_format3, 4: _write_format4, 5: _write_format5, 6: _write_format6, 7: _write_format7}
        if format_ in writers.keys():
            writer = writers[format_]
        else:
            self.log.critical("invalid format_ option (should be integer between 1 and 7 inclusive)")  # Dear future self, if hitting this message and can't figure out why, i bet it is because value of format_ is a str not an int. ;)
            exit()
        with open(filename, 'w') as f:
            for hash_ in hashes:
                line = writer(hash_)
                try:
                    f.writelines("{0}\n".format(line))
                except:
                    self.log.warning("failed to write: {0}".format(line))
                else:
                    self.log.debug("written line: {0}".format(line))

    def merge(self, hashes_1, hashes_2):
        """
        merge cracked passwords into hashes list of dictionaries
        """
        #TODO: merge properly so that we don't loose any hashes. from either list - but don't have duplicates or same hash with and without plain.
        hashes = []
        print
        print hashes_1
        print
        print hashes_2
        for hash_1 in hashes_1:
            for hash_2 in hashes_2:
                if hash_1['ntlm'] == hash_2['ntlm']:
                    #self.log.debug("hash_1: {0}".format(hash_1))
                    #self.log.debug("hash_2: {0}".format(hash_2))
                    if hash_2['passwd'] == "" and hash_1['passwd'] != "":
                        hash_2['passwd'] = hash_1['passwd']  # if hash_2 passwd is blank but hash_1 passwd is not then get the passwd from hash1. 
                    # if hash_2 passwd is not blank then it has the password so don't need to assign from hash_1
                # if the ntlm hash doesn't match then just put what we have in.
                hashes.append(hash_2)
        print
        print hashes
        print
        return hashes

    def hashcat_merge(self, hashes, hashcat_out):
        """
        merge together hashes and hashcat output
        """
        for cracked in hashcat_out:
            for hash_ in hashes:
                if cracked['ntlm'] == hash_['ntlm']:
                    hash_['passwd'] = cracked['passwd']
        return hashes

    def write_plains(self, hashes, fileprefix=""):
        """
        write plain passwords to a file in format:
        {passwd}
        """
        filename = "{0}{1}_plain.txt".format(fileprefix, datetime.strftime(datetime.now(), "%Y%m%d%H%M%S"))  # by default at 1300 on 01/02/2013 filename would be "20130201130000_plain.txt"
        plains = []
        self.log.debug("creating unique list of plains")
        for hash_ in hashes:
            try:
                hashline = "{passwd}".format(**hash_)
            except Exception as e:
                self.log.warning("failed to create hashline from: {0}".format(hash_))
                self.log.warning("{0}: {1}".format(e.errno, e.strerror))
            else:
                if hashline not in plains:  # only add a plain password if it is not in the list already
                    plains.append(hashline)
        return self._write_file(plains, filename)

    def update_discovered(self, hashes, discovered="discovered.txt"):
        """
        add plains to a file if they are not already in it.
        """
        # design decision here was made after some deliberation with a cup of tea:
        # two options. can either read the current passwords from the file into a list (in memory) and check the newly cracked hashes against it
        # or can read the file over and over again to check each password.
        # the first option is faster because we only read from the hdd once, BUT there is the strong possibility of exhausting the machine's memory.
        # the second option is going to be slower as we are repeatedly reading from the hdd (once per newly cracked hash) but won't exhaust memory.
        # decided to go for the option that is less likely to cause the machine to crash.
        self.log.debug("updating discovered passwords file")
        self.log.debug("finding unique plains")
        plains = []
        new = []
        written = 0
        failed = 0
        for hash_ in hashes:
            if hash_['passwd'] not in plains:
                plains.append(hash_['passwd'])
        self.log.debug("found {0} unique plains".format(len(plains)))

        self.log.debug("finding new plains")
        try:
            for plain in plains:
                    with open(discovered, 'r') as f:
                        if "{0}\n".format(plain) not in f:  # added \n to the end of the plain so can match the full line in the file without doing any stripping.
                            new.append(plain)
            self.log.debug("found {0} new plains".format(len(new)))
        except IOError as e:
            self.log.warning("couldn't open '{0}', creating it and assuming all plains are new.".format(discovered))
            new = plains
        else:
            # if there was no problem reading from the file - i.e. it exists. append to the file
            self.log.debug("appending new plains to file")
            try:
                with open(discovered, 'a') as h:
                    for plain in new:
                        try:
                            h.writelines("{0}\n".format(plain))
                            written += 1
                        except Exception as e:
                            self.log.warning("failed to append '{0}' to file".format(plain))
                            failed += 1
            except IOError as e:
                self.log.warning("failed to append plains to '{0}'".format(discovered))  # should be that the file doesn't exist
                self.log.warning("{0}: {1}".format(e.errno, e.strerror))
            else:
                self.log.debug("appended {0} plains to '{1}'. failed to append {2} plains".format(written, discovered, failed))
                return 0  # return after appending plains
            return 0  # return if there was an error appending plains

        #  if there was a problem reading the file (discovered) - i.e. it doesn't exist. create the file
        try:
            with open(discovered, 'w') as j:
                for plain in plains:
                    try:
                        j.writelines("{0}\n".format(plain))
                        written += 1
                    except Exception as e:
                        self.log.warning("failed to write '{0}' to file".format(plain))
                        failed += 1
        except IOError as e:
                self.log.warning("failed to write plains to '{0}'".format(discovered))  # should be that the file doesn't exist
                self.log.warning("{0}: {1}".format(e.errno, e.strerror))
                return 0
        else:
            self.log.info("written {0} plains to '{1}'. failed to write {2} plains".format(written, discovered, failed))
            return written
