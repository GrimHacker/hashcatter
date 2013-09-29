"""
.       .1111...          | Title: hashcatter
    .10000000000011.   .. | Author: Oliver Morton
 .00              000...  | Email: grimhacker@grimhacker.com
1                  01..   | Description:
                    ..    | parses a hashfile and uses ophcrack and hashcat
                   ..     | as subprocesses to crack the hashes.
GrimHacker        ..      | appends to a list of discovered plains (creating
                 ..       | a wordlist)
grimhacker.com  ..        | outputs cracked hashes
@grimhacker    ..         |
----------------------------------------------------------------------------
Created on 2 Sep 2013
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
"""
VERSION = 0.1
import argparse
import logging
import os
import sys
import Queue

from datetime import datetime
from lib.hashcat import Hashcat
from lib.ophcrack import Ophcrack
from lib.parsehashes import ParseHashes

try:
    from lib import colorlog
    COLOUR = True
except:
    COLOUR = False

# TODO:
# #add timing of ophcrack and hashcat
# #pot file for hashcat - DONE!
# #move temporary output files (ophcrack output, hash input files etc.) to system temp folder (there is a python module for this i think) delete at the end
# #move status output from ophcrack/hashcat class to a status thread - waiting on user input to/periodically display stats of number of passwords cracked from ophcrack and hashcat, in how long, and how many left. would also be able to get usernames to match hashes from hashcat.
# #support differnet hash types. will need to modify logic to hashcat _stdout and Parser() - might keep this script as is and just reuse the code for hashcat
# #duplicate ntlm hashes where one has an lm hash and the other doesn't
# ##- only crack the lm hash (using ophcrack), apply cracked password to all instances using ntlm hash as key after finished cracking
# #force ophcrack and hashcat to output to a file regardless of parameters passed from user
# #parse output files from ophcrack and hashcat merge into single output file, add newly discovered passwords to enumerated passwords list - DONE! FLAW!-merging isn't accurate, try again.
# #configuration file - ophcrack (inc tables) and hashcat (inc wordlists) config - DONE!
# #command line flag to turn off appending to enumerated passwords list.
# #any hashes that ophcrack doesn't crack from lm hash pass into a second round of hashcat?
# #unicode characters are going to break everything. need to deal with them somehow...


class Hashcatter():
    def __init__(self):
        self.log = logging.getLogger(__name__)

    def get_config(self, filename=None):
        """
        parse config file for ophcrack and hashcat options
        """
        if filename is None:
            self.log.critical("No configuration file specified.")
            exit()
        hashcat_config = {}
        ophcrack_config = {}
        with open(filename, 'r') as f:
            for line in f:
                if line.startswith("#") or line.startswith("\n"):  # comments and blank lines in the configuration file
                    continue
                else:
                    try:
                        setting = line.split("=")
                    except Exception as e:
                        self.log.warning("malformed configuration option: '{0}'".format(line))
                        continue
                    else:
                        if len(setting) != 2:
                            self.log.warning("malformed configuration option: '{0}'".format(line))
                            continue
                        else:
                            argument = setting[0].lower()  # make the setting lower case here so that we don't have to call .lower() all the time
                            option = setting[1].strip("\n")
                            if " " in option:
                                option = '"{0}"'.format(option) # if there is a space in the option enclose it in quotes.

                            # HASHCAT
                            if argument.startswith("hashcat_"):
                                argument = argument[8:]  # trims off "hashcat_".
                                # positional arguments.
                                if argument.startswith("exe"):
                                    hashcat_config[argument] = option
                                elif argument.startswith("wordlist"):
                                    if "wordlists" not in hashcat_config.keys():
                                        hashcat_config["wordlists"] = [option]  # if the wordlists option isn't already in the dictionary, add it as a list.
                                    else:
                                        hashcat_config["wordlists"].append(option)  # if the wordlists option is already in the dictionary, append to it.
                                else:
                                    # optional arguments.
                                    if argument in ["outfile", "o"]:
                                        self.log.warning("illegal config option in this context: '{0}'".format())  # can't specify an output file for hashcat or it will break running hashcat as a subprocess
                                    else:
                                        # add "-" or "--"
                                        if len(argument) == 1:
                                            argument = "-{0}".format(argument)  # if the option is a single character put "-" in front of it. e.g. "r" becomes "-r"
                                        elif len(argument) > 1:
                                            argument = "--{0}".format(argument)  # if the option is a more than a single character put "--" in front of it. e.g. "rules-file" becomes "--rules-file"
                                        else:
                                            self.log.warning("malformed hashcat option (zero or negative length): '{0}'".format(argument))
                                            continue
    
                                        if argument.startswith("-r") or argument.startswith("--rules-file"):
                                            if "-r" not in hashcat_config.keys() and "--rules-file" not in hashcat_config.keys():  # if the r option is not already in the dictionary create it as a list.
                                                try:
                                                    hashcat_config[argument] = [option]
                                                except Exception as e:
                                                    self.log.warning("failed to parse hashcat configuration option: '{0}'".format(line))
                                                    continue
                                            else:  # if the r option is already in the dictionary, append to the existing list
                                                try:
                                                    hashcat_config[argument].append(option)
                                                except Exception as e:
                                                    self.log.warning("failed to parse hashcat configuration option: {0}".format(line))
                                                    continue
                                        else:
                                            try:
                                                hashcat_config[argument] = option
                                            except Exception as e:
                                                self.log.warning("failed to parse hashcat configuration option: {0}".format(line))
                                                continue
                            # OPHCRACK
                            elif argument.startswith("ophcrack_"):
                                argument = argument[9:]  # trims off "ophcrack_"
                                if argument in ["o", "f"]:
                                    self.log.warning("illegal option in this context: '{0}'".format(argument))  # input and output files are handled internally.
                                if argument.startswith("exe"):
                                    try:
                                        ophcrack_config[argument] = option
                                    except Exception as e:
                                        self.log.warning("failed to parse ophcrack configuration option: {0}".format(line))
                                else:
                                    try:
                                        ophcrack_config["-{0}".format(argument)] = option  # at the time of writing, all ophcrack arguments are optional single characters prefixed with "-" so don't need a lot of logic
                                    except Exception as e:
                                        self.log.warning("failed to parse ophcrack configuration option: {0}".format(line))
                                        continue
                            else:
                                self.log.warning("malformed configuration option: {0}".format(line))
        return hashcat_config, ophcrack_config

    def run(self, **kwargs):
        """
        """
        fileprefix = kwargs['outfile_prefix']
        hashcat_options, ophcrack_options = self.get_config(kwargs['config'])
        parser = ParseHashes()
        if kwargs['in_format'] == 1:
            if hashcat_options["-m"] != "1000":  # 1000 is ntlm in hashcat
                self.log.critical("must specify ntlm format for hashcat if using a pwdump file.")
                exit()
            else:
                hashes = parser.read_pwdump(kwargs['hashfile'])
                if not kwargs['history']:
                    hashes = parser.remove_disabled(hashes)  # TODO: test
                if not kwargs['disabled']:
                    hashes = parser.remove_disabled(hashes)  # TODO: test
                if not kwargs['machine']:
                    hashes = parser.remove_machine(hashes)  # TODO: test
                ntlm_hashes, lm_hashes, blank_hashes = parser.separate_lm_ntlm(hashes)
                hashcat_options["hashfile"] = parser.write_hcntlm(ntlm_hashes, fileprefix)
                if kwargs['ophcrack']:
                    ophout = "{0}{1}.ophout".format(fileprefix, datetime.strftime(datetime.now(), "%Y%m%d%H%M%S"))  # by default at 1300 on 01/02/2013 filename would be "20130201130000.ophout"
                    ophcrack_options["-o"] = ophout
                    ophcrack_options["-f"] = parser.write_pwdump(lm_hashes, fileprefix)
                else:
                    ophcrack_options = None
        else:
            self.log.critical("other input formats not implemented yet :(")
            exit()

        threads = []
        hashcat_out_queue = Queue.Queue()  # queue to get output from hashcat (can either have no running output and then parse from file, or have running output and parse for hashes.)
        hashcat = Hashcat(hashcat_options, hashcat_out_queue)
        hashcat.setName("hashcat")
        threads.append(hashcat)

        if kwargs['ophcrack']:
            ophcrack = Ophcrack(ophcrack_options)
            ophcrack.setName("ophcrack")
            threads.append(ophcrack)

        # start all threads
        for thread in threads:
            thread.start()

        # wait for all threads to finish
        for thread in threads:
            thread.join()

        try:
            hashcat_raw_out = hashcat_out_queue.get_nowait()  # already waited for hashcat thread to join by now so can use get_nowait
        except Queue.Empty:
            self.log.warning("Hashcat didn't crack anything")
        else:
            hashcat_out = []
            for hash_ in hashcat_raw_out:
                plain = {'username': "", 'rid': "", 'lm': "", 'ntlm': hash_['hash'], 'pass1': "", 'pass2': "", 'passwd': hash_['passwd']}
                hashcat_out.append(plain)
            #parser.write_hcout(hashcat_out)  # writing to file during hashcat subprocess so don't need this.

        if kwargs['ophcrack']:
            try:
                ophcrack_hashes = parser.read_pwdump(ophout)
            except:
                self.log.warning("Couldn't read ophcrack output file")
                ophcrack_cracked = []
                ophcrack_uncracked = []
            else:
                ophcrack_cracked, ophcrack_uncracked = parser.separate_cracked_uncracked(ophcrack_hashes)
        else:
            ophcrack_cracked = []
            ophcrack_uncracked = []

        try:
            hashcat_hashes = parser.hashcat_merge(hashes, hashcat_out)
        except:
            self.log.warning("Couldn't create hashcat_hashes")
            hashcat_cracked = []
            hashcat_uncracked = []
        else:
            hashcat_cracked, hashcat_uncracked = parser.separate_cracked_uncracked(hashcat_hashes)

        """
        merge1 = parser.merge(hashes, hashcat_cracked)
        merge2 = parser.merge(merge1, ophcrack_cracked)
        cracked = parser.merge(merge2, blank_hashes)
        """

        if kwargs['out_format'] == 1:
            cracked, uncracked = parser.separate_cracked_uncracked(parser.merge(hashcat_hashes, ophcrack_hashes))
            if len(cracked) > 0:
                parser.write_pwdump(cracked)
            if len(uncracked) > 0:
                parser.write_pwdump(uncracked, "uncracked")
        else:
            self.log.critical("output format not implemented :(")  #TODO: hash:plain etc - same as hashcat. think the required code is already in ParseHashes
            exit()

        added = parser.update_discovered(cracked)

        self.log.info("Summary:")
        self.log.info("\t{0} plains recoverd by ophcrack".format(len(ophcrack_cracked)))
        self.log.info("\t{0} plains recoverd by hashcat".format(len(hashcat_cracked)))
        self.log.info("\t{0} blank plains recovered".format(len(blank_hashes)))
        self.log.info("\t{0} hashes cracked".format(len(cracked) + len(blank_hashes)))
        self.log.info("\t{0} hashes uncracked".format(len(uncracked)))
        self.log.info("\t{0} plains added to discovered list".format(added))
        exit()


        fileprefix = args.outfile-prefix
        # TODO:
        # #parse pwdump file into hashes
        # #if using ophcrack and hashcat:
        # #split hashes into lm and ntlm and run ophcrack and hashcat
        # #remove any ntlm hashes that are duplicated with a lm hash (only crack the lm)
        # #merge back together using ntlm as reference.
        # #create/append "enumerated" password wordlist. - DONE!
        parser = ParseHashes()
        hashes = parser.read_pwdump(args.hashfile)  # working!
        hashes = parser.remove_disabled(hashes)  # TODO: test
        hashes = parser.remove_history(hashes)  # TODO: test
        hashes = parser.remove_machine(hashes)  # TODO: test
        ntlm_hashes, lm_hashes, blank_hashes = parser.separate_lm_ntlm(hashes)  # working!

        hashcat_options, ophcrack_options = self.get_config(args.config)
        hashcat_options["hashfile"] = parser.write_hcntlm(ntlm_hashes, fileprefix)
        ophcrack_options["-o"] = "{0}{1}.ophout".format(fileprefix, datetime.strftime(datetime.now(), "%Y%m%d%H%M%S"))  # by default at 1300 on 01/02/2013 filename would be "20130201130000.ophout"
        ophcrack_options["-f"] = parser.write_pwdump(lm_hashes, fileprefix)
        #hashcat_options = {"hashcat": r"C:\Hacking\hashcat_gui-0.5.2\oclHashcat-plus-0.13\cudaHashcat-plus64.exe --status", "-r": r"C:\Hacking\hashcat_gui-0.5.2\oclHashcat-plus-0.13\rules\d3ad0ne.rule", "-m": "1000", "-a": "0", "hashfile": hcin, "wordlists": r'"C:\Hacking\Word Lists\rockyou.txt"'}
        #hashcat_options = {"hashcat": r"C:\Hacking\hashcat_gui-0.5.2\oclHashcat-plus-0.13\cudaHashcat-plus64.exe --status", "-m": "1000", "-a": "0", "hashfile": hcin, "wordlists": r'"C:\Hacking\Word Lists\rockyou.txt"'}
        #ophcrack_options = {"ophcrack": r"C:\Hacking\ophcrack\ophcrack_nogui.exe", "-d": r"C:\Hacking\ophcrack\tables", "-t": "vista_free:Vista_special:xp_free_fast:xp_free_small:XP_special", "-n": "5", "-f": ophin, "-o": ophout, "-s": r"c:\Users\GrimHacker\Python\workspace\hashcatter\src\ophcrack.session"}

        queue = Queue.Queue()  # queue to get output from hashcat (can either have no running output and then parse from file, or have running output and parse for hashes.)

        threads = []
        hashcat = Hashcat(hashcat_options, queue)
        hashcat.setName("hashcat")

        ophcrack = Ophcrack(ophcrack_options)
        ophcrack.setName("ophcrack")

        threads.append(hashcat)
        threads.append(ophcrack)

        for thread in threads:  # start all threads
            #thread.daemon = True
            thread.start()
        for thread in threads:
            thread.join()  # wait for all threads to finish

        hashcat_raw_out = []
        ophcrack_cracked = []

        try:
            hashcat_raw_out += queue.get_nowait()  # already waited for hashcat thread to join by now so can use get_nowait
        except Queue.Empty:
            self.log.warning("Hashcat didn't crack anything")
        else:
            # TODO: conditional to write hcout file or not.
            hashcat_out = []
            for hash_ in hashcat_raw_out:
                plain = {'username': "", 'rid': "", 'lm': "", 'ntlm': hash_['hash'], 'pass1': "", 'pass2': "", 'passwd': hash_['passwd']}
                hashcat_out.append(plain)
            parser.write_hcout(hashcat_out)

        # split hashes into cracked and uncracked.
        try:
            ophcrack_hashes = parser.read_pwdump(ophout)
        except:
            self.log.warning("Couldn't read ophcrack output file")
        else:
            ophcrack_cracked, ophcrack_uncracked = parser.separate_cracked_uncracked(ophcrack_hashes)

        try:
            hashcat_hashes = parser.hashcat_merge(hashes, hashcat_out)
        except:
            self.log.warning("Couldn't create hashcat_hashes")
        else:
            hashcat_cracked, hashcat_uncracked = parser.separate_cracked_uncracked(hashcat_hashes)

        self.log.debug("hashcat_cracked: {0}".format(len(hashcat_cracked)))
        self.log.debug("ophcrack_cracked: {0}".format(len(ophcrack_cracked)))

        merge1 = parser.merge(hashes, hashcat_cracked)
        merge2 = parser.merge(merge1, ophcrack_cracked)
        cracked = parser.merge(merge2, blank_hashes)
        parser.write_pwdump(cracked)

        parser.write_pwdump(parser.merge(hashcat_uncracked, ophcrack_uncracked), "uncracked")

        added = parser.update_discovered(cracked)

        self.log.info("Summary:")
        self.log.info("\t{0} plains recoverd by ophcrack".format(len(ophcrack_cracked)))
        self.log.info("\t{0} plains recoverd by hashcat".format(len(hashcat_cracked)))
        self.log.info("\t{0} blank plains recovered".format(len(blank_hashes)))
        self.log.info("\t{0} hashes cracked".format(len(ophcrack_cracked) + len(hashcat_cracked) + len(blank_hashes)))
        self.log.info("\t{0} hashes uncracked".format(len(ophcrack_uncracked) + len(hashcat_uncracked)))
        self.log.info("\t{0} plains added to discovered list".format(added))

if __name__ == '__main__':
    def main(args):
        hascatter = Hashcatter()
        hascatter.run(**vars(args))  # vars() converts class to dict

    def version():
        print """
.       .1111...          | Title:  hashcatter VERSION: {0}
    .10000000000011.   .. | Author: Oliver Morton
 .00              000...  | Email: grimhacker@grimhacker.com
1                  01..   | Description:
                    ..    | parses a hashfile and uses ophcrack and hashcat
                   ..     | as subprocesses to crack the hashes.
GrimHacker        ..      | appends to a list of discovered plains (creating
                 ..       | a wordlist)
grimhacker.com  ..        | outputs cracked hashes
@grimhacker    ..         |
----------------------------------------------------------------------------
""".format(VERSION)

    def logConfig(verbosity, filename=None):
        """
        setup logging.
        verbosity expects 1,2,3,4,5
        filename expects a string that specifies the filename to save the log to (.log
        is appended)
        """
        if args.verbosity == 1:
            vlevel = logging.CRITICAL
        elif args.verbosity == 2:
            vlevel = logging.ERROR
        elif args.verbosity == 3:
            vlevel = logging.WARNING
        elif args.verbosity == 4:
            vlevel = logging.INFO
        elif args.verbosity == 5:
            vlevel = logging.DEBUG
        else:
            assert "Error unacceptable verbosity level specify 1,2,3,4 or 5"

        vlevel = logging.DEBUG
        if filename:
            # when logging to a file use prefix the entry with the date and time. also output to the console without date and time.
            filename = str(filename) + ".log"
            logging.basicConfig(filename=filename, filemode='w', format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG, datefmt='%y.%m.%d %H:%M:%S')
            if COLOUR:
                #if colouring is supported colourise the streamhandler, rest of the config is handled later
                console = colorlog.ColorizingStreamHandler(sys.stdout)
            else:
                #if colouring is not supported just define a new stream handler
                console = logging.StreamHandler()  # defines a handler
            #do the rest of the config for the console stream handler
            console.setLevel(vlevel)  # set level of messages to log on console
            formatter = logging.Formatter('%(levelname)s: %(message)s')  # sets format for messages on console
            console.setFormatter(formatter)  # uses format set above
            logging.getLogger('').addHandler(console)  # add handler to root logger
        else:
            # if not logging to a file, set basic config for logging to console
            if COLOUR:
                #if colouring is supported colourise the stream handler and do the config
                console = colorlog.ColorizingStreamHandler(sys.stdout)
                formatter = logging.Formatter('%(levelname)s: %(message)s')
                console.setFormatter(formatter)
                logging.getLogger('').addHandler(console)
                logging.getLogger('').setLevel(vlevel)
            else:
                #if colouring is not supported do normal logging basic config.
                logging.basicConfig(format='%(levelname)s: %(message)s', level=vlevel)

######################################################################
    parser = argparse.ArgumentParser(prog="", description="")
    parser.add_argument("--version", help="Display the version banner", action="store_true")
    parser.add_argument("-v", "--verbosity", help="Verbosity of output. 1 = CRITICAL, 5 = DEBUG", type=int, choices=[1, 2, 3, 4, 5], default=4)
    parser.add_argument("-l", "--log", help="log file", default="log.txt")
    parser.add_argument("-O", "--ophcrack", help="disable ophcrack", action="store_false")
    parser.add_argument("-o", "--outfile_prefix", help="output file prefix", default="")
    parser.add_argument("-c", "--config", help="hashcat/ophcrack config file", default=os.path.join("conf", "CONFIG"))
    parser.add_argument("-D", "--discovered", help="file to append discovered plains to", default="discovered.txt")
    parser.add_argument("-f", "--in_format", help="input hashfile format. 1=PWDUMP, 2=HASH", choices=[1, 2], default=1)
    parser.add_argument("-F", "--out_format", help="output hashfile format. 1=PWDUMP, 2=HASH:PLAIN", choices=[1, 2], default=1)
    parser.add_argument("--disabled", help="keep disabled accounts", action="store_true")
    parser.add_argument("--history", help="keep history accounts", action="store_true")
    parser.add_argument("--machine", help="keep machine accounts", action="store_true")
    parser.add_argument("hashfile")

    args = parser.parse_args()

    if args.version:
        version()
        exit()

    logConfig(args.verbosity, args.log)

    main(args)
