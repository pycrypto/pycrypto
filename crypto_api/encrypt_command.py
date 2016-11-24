# coding=utf-8
"""
 Command line utility for encryption of files and folders
"""

# coding=utf-8
import os
from argparse import ArgumentParser
#noinspection PyBroadException
try:
    #noinspection PyUnresolvedReferences
    from crypto_api import *
except:
    from __init__ import *

def perc_callback(perc):
    """
    test
    :param perc:
    @param perc:
    """
    print perc


def main():
    """
    main
    """
    parser = ArgumentParser()
    parser.add_argument("-k", "--key", dest="key", help="secret key", metavar="password")
    parser.add_argument("-e", "--encrypt", dest="encrypt", help="encrypt file or directory", metavar=1)
    parser.add_argument("-d", "--decrypt", dest="decrypt", help="decrypt file or directory", metavar=1)
    parser.add_argument("-t", "--target", dest="target", help="target file or directory", metavar="name")

    args = parser.parse_args()
    if args.key and args.target:
        if args.encrypt > 0:
            print "encrypting", args.target
            if os.path.isdir(args.target):
                os.system("tar -cf "+args.target.strip("/")+".tar ./"+args.target)
                encrypt_file(args.key, args.target.strip("/")+".tar", perc_callback)
                os.system("rm -Rf "+args.target)
                os.system("rm "+args.target.strip("/")+".tar")
            else:
                encrypt_file(args.key,  args.target, perc_callback)
                os.system("rm "+args.target)

        if args.decrypt > 0:
            if ".tar" in args.target:
                decrypt_file(args.key, args.target, perc_callback)
                os.system("tar xf ./"+args.target.rstrip(".enc"))
                os.system("rm "+args.target.rstrip(".enc"))
            else:
                decrypt_file(args.key, args.target, perc_callback)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
