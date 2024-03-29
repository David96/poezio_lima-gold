# Copyright 2010-2011 Florent Le Coz <louiz@louiz.org>
#
# This file is part of Poezio.
#
# Poezio is free software: you can redistribute it and/or modify
# it under the terms of the zlib license. See the COPYING file.

"""
Various useful functions.
"""

from datetime import datetime, timedelta
from slixmpp import JID, InvalidJID
from poezio.poezio_shlex import shlex

import base64
import os
import mimetypes
import hashlib
import subprocess
import time
import string


def get_base64_from_file(path):
    """
    Convert the content of a file to base64

    :param str path: The path of the file to convert.
    :return: A tuple of (encoded data, mime type, sha1 hash) if
        the file exists and does not exceeds the upper size limit of 16384.
    :return: (None, None, error message) if it fails
    :rtype: :py:class:`tuple`

    """
    if not os.path.isfile(path):
        return (None, None, "File does not exist")
    size = os.path.getsize(path)
    if size > 16384:
        return (None, None, "File is too big")
    fdes = open(path, 'rb')
    data = fdes.read()
    encoded = base64.encodestring(data)
    sha1 = hashlib.sha1(data).hexdigest()
    mime_type = mimetypes.guess_type(path)[0]
    return (encoded, mime_type, sha1)

def _get_output_of_command(command):
    """
    Runs a command and returns its output.

    :param str command: The command to run.
    :return: The output or None
    :rtype: :py:class:`str`
    """
    try:
        return subprocess.check_output(command.split()).decode('utf-8').split('\n')
    except subprocess.CalledProcessError:
        return None

def _is_in_path(command, return_abs_path=False):
    """
    Check if *command* is in the $PATH or not.

    :param str command: The command to be checked.
    :param bool return_abs_path: Return the absolute path of the command instead
        of True if the command is found.
    :return: True if the command is found, the command path if the command is found
        and *return_abs_path* is True, otherwise False.

    """
    for directory in os.getenv('PATH').split(os.pathsep):
        try:
            if command in os.listdir(directory):
                if return_abs_path:
                    return os.path.join(directory, command)
                else:
                    return True
        except OSError:
            # If the user has non directories in his path
            pass
    return False

DISTRO_INFO = {
    'Arch Linux': '/etc/arch-release',
    'Aurox Linux': '/etc/aurox-release',
    'Conectiva Linux': '/etc/conectiva-release',
    'CRUX': '/usr/bin/crux',
    'Debian GNU/Linux': '/etc/debian_version',
    'Fedora Linux': '/etc/fedora-release',
    'Gentoo Linux': '/etc/gentoo-release',
    'Linux from Scratch': '/etc/lfs-release',
    'Mandrake Linux': '/etc/mandrake-release',
    'Slackware Linux': '/etc/slackware-version',
    'Solaris/Sparc': '/etc/release',
    'Source Mage': '/etc/sourcemage_version',
    'SUSE Linux': '/etc/SuSE-release',
    'Sun JDS': '/etc/sun-release',
    'PLD Linux': '/etc/pld-release',
    'Yellow Dog Linux': '/etc/yellowdog-release',
    # many distros use the /etc/redhat-release for compatibility
    # so Redhat is the last
    'Redhat Linux': '/etc/redhat-release'
}

def get_os_info():
    """
    Returns a detailed and well formated string containing
    informations about the operating system

    :rtype: str
    """
    if os.name == 'posix':
        executable = 'lsb_release'
        params = ' --description --codename --release --short'
        full_path_to_executable = _is_in_path(executable, return_abs_path=True)
        if full_path_to_executable:
            command = executable + params
            process = subprocess.Popen([command], shell=True,
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE,
                                       close_fds=True)
            process.wait()
            output = process.stdout.readline().decode('utf-8').strip()
            # some distros put n/a in places, so remove those
            output = output.replace('n/a', '').replace('N/A', '')
            return output

        # lsb_release executable not available, so parse files
        for distro_name in DISTRO_INFO:
            path_to_file = DISTRO_INFO[distro_name]
            if os.path.exists(path_to_file):
                if os.access(path_to_file, os.X_OK):
                    # the file is executable (f.e. CRUX)
                    # yes, then run it and get the first line of output.
                    text = _get_output_of_command(path_to_file)[0]
                else:
                    fdes = open(path_to_file, encoding='utf-8')
                    text = fdes.readline().strip() # get only first line
                    fdes.close()
                    if path_to_file.endswith('version'):
                        # sourcemage_version and slackware-version files
                        # have all the info we need (name and version of distro)
                        if not os.path.basename(path_to_file).startswith(
                                'sourcemage') or not\
                                os.path.basename(path_to_file).startswith('slackware'):
                            text = distro_name + ' ' + text
                    elif path_to_file.endswith('aurox-release') or \
                            path_to_file.endswith('arch-release'):
                        # file doesn't have version
                        text = distro_name
                    elif path_to_file.endswith('lfs-release'):
                        # file just has version
                        text = distro_name + ' ' + text
                os_info = text.replace('\n', '')
                return os_info

        # our last chance, ask uname and strip it
        uname_output = _get_output_of_command('uname -sr')
        if uname_output is not None:
            os_info = uname_output[0] # only first line
            return os_info
    os_info = 'N/A'
    return os_info

def _datetime_tuple(timestamp):
    """
    Convert a timestamp using strptime and the format: %Y%m%dT%H:%M:%S.

    Because various datetime formats are used, the following exceptions
    are handled:

    * Optional milliseconds appened to the string are removed
    * Optional Z (that means UTC) appened to the string are removed
    * XEP-082 datetime strings have all '-' chars removed to meet the above format.

    :param str timestamp: The string containing the formatted date.
    :return: The date.
    :rtype: :py:class:`datetime.datetime`
    """
    timestamp = timestamp.replace('-', '', 2).replace(':', '')
    date = timestamp[:15]
    tz_msg = timestamp[15:]
    try:
        ret = datetime.strptime(date, '%Y%m%dT%H%M%S')
    except ValueError:
        ret = datetime.now()
    # add the message timezone if any
    try:
        if tz_msg and tz_msg != 'Z':
            tz_mod = -1 if tz_msg[0] == '-' else 1
            tz_msg = time.strptime(tz_msg[1:], '%H%M')
            tz_msg = tz_msg.tm_hour * 3600 + tz_msg.tm_min * 60
            tz_msg = timedelta(seconds=tz_mod * tz_msg)
            ret -= tz_msg
    except ValueError:
        pass # ignore if we got a badly-formatted offset
    # convert UTC to local time, with DST etc.
    if time.daylight and time.localtime().tm_isdst:
        tz = timedelta(seconds=-time.altzone)
    else:
        tz = timedelta(seconds=-time.timezone)
    ret += tz
    return ret

def get_utc_time(local_time=None):
    """
    Get the current UTC time

    :param datetime local_time: The current local time
    :return: The current UTC time
    """
    if local_time is None:
        local_time = datetime.now()
        isdst = time.localtime().tm_isdst
    else:
        isdst = time.localtime(int(local_time.timestamp())).tm_isdst

    if time.daylight and isdst:
        tz = timedelta(seconds=time.altzone)
    else:
        tz = timedelta(seconds=time.timezone)

    utc_time = local_time + tz

    return utc_time

def get_local_time(utc_time):
    """
    Get the local time from an UTC time
    """
    isdst = time.localtime(int(utc_time.timestamp())).tm_isdst

    if time.daylight and isdst:
        tz = timedelta(seconds=time.altzone)
    else:
        tz = timedelta(seconds=time.timezone)

    local_time = utc_time - tz

    return local_time

def find_delayed_tag(message):
    """
    Check if a message is delayed or not.

    :param slixmpp.Message message: The message to check.
    :return: A tuple containing (True, the datetime) or (False, None)
    :rtype: :py:class:`tuple`
    """

    delay_tag = message.find('{urn:xmpp:delay}delay')
    if delay_tag is not None:
        delayed = True
        date = _datetime_tuple(delay_tag.attrib['stamp'])
    else:
        # We support the OLD and deprecated XEP: http://xmpp.org/extensions/xep-0091.html
        # But it sucks, please, Jabber servers, don't do this :(
        delay_tag = message.find('{jabber:x:delay}x')
        if delay_tag is not None:
            delayed = True
            date = _datetime_tuple(delay_tag.attrib['stamp'])
        else:
            delayed = False
            date = None
    return (delayed, date)

def shell_split(st):
    """
    Split a string correctly according to the quotes
    around the elements.

    :param str st: The string to split.
    :return: A list of the different of the string.
    :rtype: :py:class:`list`

    >>> shell_split('"sdf 1" "toto 2"')
    ['sdf 1', 'toto 2']
    """
    sh = shlex(st)
    ret = []
    w = sh.get_token()
    while w and w[2] is not None:
        ret.append(w[2])
        if w[1] == len(st):
            return ret
        w = sh.get_token()
    return ret

def find_argument(pos, text, quoted=True):
    """
    Split an input into a list of arguments, return the number of the
    argument selected by pos.

    If the position searched is outside the string, or in a space between words,
    then it will return the position of an hypothetical new argument.

    See the doctests of the two methods for example behaviors.

    :param int pos: The position to search.
    :param str text: The text to analyze.
    :param bool quoted: Whether to take quotes into account or not.
    :rtype: int
    """
    if quoted:
        return _find_argument_quoted(pos, text)
    else:
        return _find_argument_unquoted(pos, text)

def _find_argument_quoted(pos, text):
    """
    Get the number of the argument at position pos in
    a string with possibly quoted text.
    """
    sh = shlex(text)
    count = -1
    w = sh.get_token()
    while w and w[2] is not None:
        count += 1
        if w[0] <= pos < w[1]:
            return count
        w = sh.get_token()

    return count + 1

def _find_argument_unquoted(pos, text):
    """
    Get the number of the argument at position pos in
    a string without interpreting quotes.
    """
    ret = text.split()
    search = 0
    argnum = 0
    for i, elem in enumerate(ret):
        elem_start = text.find(elem, search)
        elem_end = elem_start + len(elem)
        search = elem_end
        if elem_start <= pos < elem_end:
            return i
        argnum = i
    return argnum + 1

def parse_str_to_secs(duration=''):
    """
    Parse a string of with a number of d, h, m, s.

    :param str duration: The formatted string.
    :return: The number of seconds represented by the string
    :rtype: :py:class:`int`

    >>> parse_str_to_secs("1d3m1h")
    90180
    """
    values = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
    result = 0
    tmp = '0'
    for char in duration:
        if char in string.digits:
            tmp += char
        elif char in values:
            tmp_i = int(tmp)
            result += tmp_i * values[char]
            tmp = '0'
        else:
            return 0
    if tmp != '0':
        result += int(tmp)
    return result

def parse_secs_to_str(duration=0):
    """
    Do the reverse operation of :py:func:`parse_str_to_secs`.

    Parse a number of seconds to a human-readable string.
    The string has the form XdXhXmXs. 0 units are removed.

    :param int duration: The duration, in seconds.
    :return: A formatted string containing the duration.
    :rtype: :py:class:`str`

    >>> parse_secs_to_str(3601)
    '1h1s'
    """
    secs, mins, hours, days = 0, 0, 0, 0
    result = ''
    secs = duration % 60
    mins = (duration % 3600) // 60
    hours = (duration % 86400) // 3600
    days = duration // 86400

    result += '%dd' % days if days else ''
    result += '%dh' % hours if hours else ''
    result += '%dm' % mins if mins else ''
    result += '%ds' % secs if secs else ''
    if not result:
        result = '0s'
    return result

def format_tune_string(infos):
    """
    Contruct a string from a dict created from an "User tune" event.

    :param dict infos: The informations
    :return: The formatted string
    :rtype: :py:class:`str`
    """
    elems = []
    track = infos.get('track')
    if track:
        elems.append(track)
    title = infos.get('title')
    if title:
        elems.append(title)
    else:
        elems.append('Unknown title')
    elems.append('-')
    artist = infos.get('artist')
    if artist:
        elems.append(artist)
    else:
        elems.append('Unknown artist')

    rating = infos.get('rating')
    if rating:
        elems.append('[ ' + rating + '/10 ]')
    length = infos.get('length')
    if length:
        length = int(length)
        secs = length % 60
        mins = length // 60
        secs = str(secs).zfill(2)
        mins = str(mins).zfill(2)
        elems.append('[' + mins + ':' + secs + ']')
    return ' '.join(elems)

def format_gaming_string(infos):
    """
    Construct a string from a dict containing the "user gaming"
    informations.
    (for now, only use address and name)

    :param dict infos: The informations
    :returns: The formatted string
    :rtype: :py:class:`str`
    """
    name = infos.get('name')
    if not name:
        return ''

    server_address = infos.get('server_address')
    if server_address:
        return '%s on %s' % (name, server_address)
    return name

def safeJID(*args, **kwargs):
    """
    Construct a :py:class:`slixmpp.JID` object from a string.

    Used to avoid tracebacks during is stringprep fails
    (fall back to a JID with an empty string).
    """
    try:
        return JID(*args, **kwargs)
    except InvalidJID:
        return JID('')

