#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Check whether jars are signed

import glob
import logging
import os
import subprocess
import sys


def usage():
    return ("""\
%s [-v] dir1 [dir2 ...]
  Attempts to verify the signing status of all jars in a directory (not
  recursive). Prints out a summary line, e.g.:
    2/5 signed 2 warn 1 unknown-cert 1 not-timestamped 1 no-manifest
  -v Print out a status line for every jar""" % os.path.basename(__file__))


class Stop(Exception):
    def __init__(self, rc, *args, **kwargs):
        self.rc = rc
        super(Stop, self).__init__(*args, **kwargs)


class Status(object):
    def __init__(self, jarname):
        self.jarname = jarname
        self.verified = None
        self.warning = None
        self.unknowncert = None
        self.notimestamp = None
        self.nomanifest = None
        self.expiresoon = None

    def __str__(self):
        s = '%s %s' % (self.jarname, 'Signed' if self.verified else 'Unsigned')
        if self.warning:
            s += ' warning'
        if self.unknowncert:
            s += ' unknown-cert'
        if self.notimestamp:
            s += ' no-timestamp'
        if self.nomanifest:
            s += ' no-manifest'
        if self.expiresoon:
            s += ' expire-soon'
        return s


def parse_jarsigner_verify(jarname, out):
    s = Status(jarname)

    lines = out.split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue
        elif line == 'jar verified.':
            assert s.verified is None
            s.verified = True
        elif line.startswith('jar is unsigned.'):
            assert s.verified is None
            s.verified = False
        elif line == 'Warning:':
            assert s.warning is None
            s.warning = True
        elif line == 'no manifest.':
            assert s.nomanifest is None
            s.nomanifest = True
        elif line.startswith('This jar contains entries whose certificate '
                             'chain is not validated.'):
            assert s.unknowncert is None
            s.unknowncert = True
        elif line.startswith('This jar contains signatures that does not '
                             'include a timestamp.'):
            assert s.notimestamp is None
            s.notimestamp = True
        elif line.startswith('This jar contains entries whose signer '
                              'certificate will expire within six months.'):
            assert s.expiresoon is None
            s.expiresoon = True
        elif line.startswith('Re-run with the -verbose and -certs options for'
                             ' more details.'):
            continue
        else:
            raise Stop(2, 'Unexpected output: for %s %s' % (jarname, lines))

    return s


def jarverify(jar):
    cmd = ['jarsigner', '-verify', jar]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        # jarsigner returns 0 irrespective of whether the jar was verified or
        # not
        raise Stop(proc.returncode, 'Failed to run %s' % cmd)
    logging.info('Signed %s', jar)

    if err:
        raise Stop(2, 'Unexpected error output from %s\n%s' % (cmd, err))
    if not out:
        raise Stop(2, 'No output received from %s' % cmd)

    status = parse_jarsigner_verify(jar, out)
    return status


def verify_jar_directory(d, verbose=0):
    if not os.path.isdir(d):
        raise Stop(3, 'Directory %s not found' % d)
    jars = glob.glob(os.path.join(d, '*.jar'))
    statuses = []
    for jar in jars:
        status = jarverify(jar)
        statuses.append(status)
        if verbose:
            print status
    return statuses


def summarise_statuses(statuses):
    signed = 0
    warning = 0
    unknowncert = 0
    notimestamp = 0
    nomanifest = 0
    expiresoon = 0
    total = len(statuses)

    for s in statuses:
        if s.verified:
            signed += 1
        if s.warning:
            warning += 1
        if s.unknowncert:
            unknowncert += 1
        if s.notimestamp:
            notimestamp += 1
        if s.nomanifest:
            nomanifest += 1
        if s.expiresoon:
            expiresoon += 1

    return ('%d/%d signed %d warn %d unknown-cert %d not-timestamped %d '
            'no-manifest %d expire-soon' % (
                signed, total, warning, unknowncert, notimestamp, nomanifest,
                expiresoon))


def main(args):
    if len(args) < 2:
        raise Stop(1, usage())
    if args[1] == '-v':
        verbose = 1
        dirs = sys.argv[2:]
    else:
        verbose = 0
        dirs = sys.argv[1:]
    if len(dirs) < 1:
        raise Stop(1, usage())

    statuses = []
    for d in dirs:
        statuses.extend(verify_jar_directory(d, verbose))
    s = summarise_statuses(statuses)
    print s


if __name__ == '__main__':
    try:
        main(sys.argv)
    except Stop as e:
        sys.stderr.write('ERROR: %s\n' % e)
        sys.exit(e.rc)
