"""
Module for the base Tabs

The root class Tab defines the generic interface and attributes of a
tab. A tab organizes various Windows around the screen depending
of the tab specificity. If the tab shows messages, it will also
reference a buffer containing the messages.

Each subclass should redefine its own refresh() and resize() method
according to its windows.

This module also defines ChatTabs, the parent class for all tabs
revolving around chats.
"""

import logging
log = logging.getLogger(__name__)

import string
import time
from xml.etree import cElementTree as ET

from poezio.core.structs import Command
from poezio import timed_events
from poezio import windows
from poezio import xhtml
from poezio.common import safeJID
from poezio.config import config
from poezio.decorators import refresh_wrapper
from poezio.logger import logger
from poezio.text_buffer import TextBuffer
from poezio.theming import get_theme, dump_tuple
from poezio.decorators import command_args_parser

# getters for tab colors (lambdas, so that they are dynamic)
STATE_COLORS = {
        'disconnected': lambda: get_theme().COLOR_TAB_DISCONNECTED,
        'scrolled': lambda: get_theme().COLOR_TAB_SCROLLED,
        'nonempty': lambda: get_theme().COLOR_TAB_NONEMPTY,
        'joined': lambda: get_theme().COLOR_TAB_JOINED,
        'message': lambda: get_theme().COLOR_TAB_NEW_MESSAGE,
        'composing': lambda: get_theme().COLOR_TAB_COMPOSING,
        'highlight': lambda: get_theme().COLOR_TAB_HIGHLIGHT,
        'private': lambda: get_theme().COLOR_TAB_PRIVATE,
        'normal': lambda: get_theme().COLOR_TAB_NORMAL,
        'current': lambda: get_theme().COLOR_TAB_CURRENT,
        'attention': lambda: get_theme().COLOR_TAB_ATTENTION,
    }
VERTICAL_STATE_COLORS = {
        'disconnected': lambda: get_theme().COLOR_VERTICAL_TAB_DISCONNECTED,
        'scrolled': lambda: get_theme().COLOR_VERTICAL_TAB_SCROLLED,
        'nonempty': lambda: get_theme().COLOR_VERTICAL_TAB_NONEMPTY,
        'joined': lambda: get_theme().COLOR_VERTICAL_TAB_JOINED,
        'message': lambda: get_theme().COLOR_VERTICAL_TAB_NEW_MESSAGE,
        'composing': lambda: get_theme().COLOR_VERTICAL_TAB_COMPOSING,
        'highlight': lambda: get_theme().COLOR_VERTICAL_TAB_HIGHLIGHT,
        'private': lambda: get_theme().COLOR_VERTICAL_TAB_PRIVATE,
        'normal': lambda: get_theme().COLOR_VERTICAL_TAB_NORMAL,
        'current': lambda: get_theme().COLOR_VERTICAL_TAB_CURRENT,
        'attention': lambda: get_theme().COLOR_VERTICAL_TAB_ATTENTION,
    }


# priority of the different tab states when using Alt+e
# higher means more priority, < 0 means not selectable
STATE_PRIORITY = {
        'normal': -1,
        'current': -1,
        'disconnected': 0,
        'nonempty': 0.1,
        'scrolled': 0.5,
        'joined': 0.8,
        'composing': 0.9,
        'message': 1,
        'highlight': 2,
        'private': 2,
        'attention': 3
    }

class Tab(object):
    plugin_commands = {}
    plugin_keys = {}
    def __init__(self, core):
        self.core = core
        if not hasattr(self, 'name'):
            self.name = self.__class__.__name__
        self.input = None
        self.closed = False
        self._state = 'normal'
        self._prev_state = None

        self.need_resize = False
        self.key_func = {}      # each tab should add their keys in there
                                # and use them in on_input
        self.commands = {}      # and their own commands


    @property
    def size(self):
        return self.core.size

    @property
    def nb(self):
        for index, tab in enumerate(self.core.tabs):
            if tab == self:
                return index
        return len(self.core.tabs)

    @staticmethod
    def tab_win_height():
        """
        Returns 1 or 0, depending on if we are using the vertical tab list
        or not.
        """
        if config.get('enable_vertical_tab_list'):
            return 0
        return 1

    @property
    def info_win(self):
        return self.core.information_win

    @property
    def color(self):
        return STATE_COLORS[self._state]()

    @property
    def vertical_color(self):
        return VERTICAL_STATE_COLORS[self._state]()

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        if not value in STATE_COLORS:
            log.debug("Invalid value for tab state: %s", value)
        elif STATE_PRIORITY[value] < STATE_PRIORITY[self._state] and \
                value not in ('current', 'disconnected') and \
                not (self._state == 'scrolled' and value == 'disconnected'):
            log.debug("Did not set state because of lower priority, asked: %s, kept: %s", value, self._state)
        elif self._state == 'disconnected' and value not in ('joined', 'current'):
            log.debug('Did not set state because disconnected tabs remain visible')
        else:
            self._state = value
            if self._state == 'current':
                self._prev_state = None

    def set_state(self, value):
        self._state = value

    def save_state(self):
        if self._state != 'composing':
            self._prev_state = self._state

    def restore_state(self):
        if self.state == 'composing' and self._prev_state:
            self._state = self._prev_state
            self._prev_state = None
        elif not self._prev_state:
            self._state = 'normal'

    @staticmethod
    def resize(scr):
        Tab.height, Tab.width = scr.getmaxyx()
        windows.base_wins.TAB_WIN = scr

    def missing_command_callback(self, command_name):
        """
        Callback executed when a command is not found.
        Returns True if the callback took care of displaying
        the error message, False otherwise.
        """
        return False

    def register_command(self, name, func, *, desc='', shortdesc='', completion=None, usage=''):
        """
        Add a command
        """
        if name in self.commands:
            return
        if not desc and shortdesc:
            desc = shortdesc
        self.commands[name] = Command(func, desc, completion, shortdesc, usage)

    def complete_commands(self, the_input):
        """
        Does command completion on the specified input for both global and tab-specific
        commands.
        This should be called from the completion method (on tab, for example), passing
        the input where completion is to be made.
        It can completion the command name itself or an argument of the command.
        Returns True if a completion was made, False else.
        """
        txt = the_input.get_text()
        # check if this is a command
        if txt.startswith('/') and not txt.startswith('//'):
            position = the_input.get_argument_position(quoted=False)
            if position == 0:
                words = ['/%s'% (name) for name in sorted(self.core.commands)] +\
                    ['/%s' % (name) for name in sorted(self.commands)]
                the_input.new_completion(words, 0)
                # Do not try to cycle command completion if there was only
                # one possibily. The next tab will complete the argument.
                # Otherwise we would need to add a useless space before being
                # able to complete the arguments.
                hit_copy = set(the_input.hit_list)
                while not hit_copy:
                    whitespace = the_input.text.find(' ')
                    if whitespace == -1:
                        whitespace = len(the_input.text)
                    the_input.text = the_input.text[:whitespace-1] + the_input.text[whitespace:]
                    the_input.new_completion(words, 0)
                    hit_copy = set(the_input.hit_list)
                if len(hit_copy) == 1:
                    the_input.do_command(' ')
                    the_input.reset_completion()
                return True
            # check if we are in the middle of the command name
            elif len(txt.split()) > 1 or\
                    (txt.endswith(' ') and not the_input.last_completion):
                command_name = txt.split()[0][1:]
                if command_name in self.commands:
                    command = self.commands[command_name]
                elif command_name in self.core.commands:
                    command = self.core.commands[command_name]
                else:           # Unknown command, cannot complete
                    return False
                if command.comp is None:
                    return False # There's no completion function
                else:
                    return command.comp(the_input)
        return False

    def execute_command(self, provided_text):
        """
        Execute the command in the input and return False if
        the input didn't contain a command
        """
        txt = provided_text or self.input.key_enter()
        if txt.startswith('/') and not txt.startswith('//') and\
                not txt.startswith('/me '):
            command = txt.strip().split()[0][1:]
            arg = txt[2+len(command):] # jump the '/' and the ' '
            func = None
            if command in self.commands: # check tab-specific commands
                func = self.commands[command].func
            elif command in self.core.commands: # check global commands
                func = self.core.commands[command].func
            else:
                low = command.lower()
                if low in self.commands:
                    func = self.commands[low].func
                elif low in self.core.commands:
                    func = self.core.commands[low].func
                else:
                    if self.missing_command_callback is not None:
                        error_handled = self.missing_command_callback(low)
                    if not error_handled:
                        self.core.information("Unknown command (%s)" %
                                              (command),
                                              'Error')
            if command in ('correct', 'say'): # hack
                arg = xhtml.convert_simple_to_full_colors(arg)
            else:
                arg = xhtml.clean_text_simple(arg)
            if func:
                if hasattr(self.input, "reset_completion"):
                    self.input.reset_completion()
                func(arg)
            return True
        else:
            return False

    def refresh_tab_win(self):
        if config.get('enable_vertical_tab_list'):
            left_tab_win = self.core.left_tab_win
            if left_tab_win and not self.size.core_degrade_x:
                left_tab_win.refresh()
        elif not self.size.core_degrade_y:
            self.core.tab_win.refresh()

    def refresh(self):
        """
        Called on each screen refresh (when something has changed)
        """
        pass

    def get_name(self):
        """
        get the name of the tab
        """
        return self.name

    def get_nick(self):
        """
        Get the nick of the tab (defaults to its name)
        """
        return self.name

    def get_text_window(self):
        """
        Returns the principal TextWin window, if there's one
        """
        return None

    def on_input(self, key, raw):
        """
        raw indicates if the key should activate the associated command or not.
        """
        pass

    def update_commands(self):
        for c in self.plugin_commands:
            if not c in self.commands:
                self.commands[c] = self.plugin_commands[c]

    def update_keys(self):
        for k in self.plugin_keys:
            if not k in self.key_func:
                self.key_func[k] = self.plugin_keys[k]

    def on_lose_focus(self):
        """
        called when this tab loses the focus.
        """
        self.state = 'normal'

    def on_gain_focus(self):
        """
        called when this tab gains the focus.
        """
        self.state = 'current'

    def on_scroll_down(self):
        """
        Defines what happens when we scroll down
        """
        pass

    def on_scroll_up(self):
        """
        Defines what happens when we scroll up
        """
        pass

    def on_line_up(self):
        """
        Defines what happens when we scroll one line up
        """
        pass

    def on_line_down(self):
        """
        Defines what happens when we scroll one line up
        """
        pass

    def on_half_scroll_down(self):
        """
        Defines what happens when we scroll half a screen down
        """
        pass

    def on_half_scroll_up(self):
        """
        Defines what happens when we scroll half a screen up
        """
        pass

    def on_info_win_size_changed(self):
        """
        Called when the window with the informations is resized
        """
        pass

    def on_close(self):
        """
        Called when the tab is to be closed
        """
        if self.input:
            self.input.on_delete()
        self.closed = True

    def matching_names(self):
        """
        Returns a list of strings that are used to name a tab with the /win
        command.  For example you could switch to a tab that returns
        ['hello', 'coucou'] using /win hel, or /win coucou
        If not implemented in the tab, it just doesn’t match with anything.
        """
        return []

    def __del__(self):
        log.debug('------ Closing tab %s', self.__class__.__name__)

class GapTab(Tab):

    def __bool__(self):
        return False

    def __len__(self):
        return 0

    @property
    def name(self):
        return ''

    def refresh(self):
        log.debug('WARNING: refresh() called on a gap tab, this should not happen')

class ChatTab(Tab):
    """
    A tab containing a chat of any type.
    Just use this class instead of Tab if the tab needs a recent-words completion
    Also, ^M is already bound to on_enter
    And also, add the /say command
    """
    plugin_commands = {}
    plugin_keys = {}
    def __init__(self, core, jid=''):
        Tab.__init__(self, core)
        self.name = jid
        self.text_win = None
        self._text_buffer = TextBuffer()
        self.chatstate = None   # can be "active", "composing", "paused", "gone", "inactive"
        # We keep a reference of the event that will set our chatstate to "paused", so that
        # we can delete it or change it if we need to
        self.timed_event_paused = None
        # Keeps the last sent message to complete it easily in completion_correct, and to replace it.
        self.last_sent_message = None
        self.key_func['M-v'] = self.move_separator
        self.key_func['M-h'] = self.scroll_separator
        self.key_func['M-/'] = self.last_words_completion
        self.key_func['^M'] = self.on_enter
        self.register_command('say', self.command_say,
                usage='<message>',
                shortdesc='Send the message.')
        self.register_command('xhtml', self.command_xhtml,
                usage='<custom xhtml>',
                shortdesc='Send custom XHTML.')
        self.register_command('clear', self.command_clear,
                shortdesc='Clear the current buffer.')
        self.register_command('correct', self.command_correct,
                desc='Fix the last message with whatever you want.',
                shortdesc='Correct the last message.',
                completion=self.completion_correct)
        self.chat_state = None
        self.update_commands()
        self.update_keys()

        # Get the logs
        log_nb = config.get('load_log')
        logs = self.load_logs(log_nb)

        if logs:
            for message in logs:
                self._text_buffer.add_message(**message)

    @property
    def is_muc(self):
        return False

    def load_logs(self, log_nb):
        logs = logger.get_logs(safeJID(self.name).bare, log_nb)
        return logs

    def log_message(self, txt, nickname, time=None, typ=1):
        """
        Log the messages in the archives.
        """
        name = safeJID(self.name).bare
        if not logger.log_message(name, nickname, txt, date=time, typ=typ):
            self.core.information('Unable to write in the log file', 'Error')

    def add_message(self, txt, time=None, nickname=None, forced_user=None,
                    nick_color=None, identifier=None, jid=None, history=None,
                    typ=1, highlight=False):
        self.log_message(txt, nickname, time=time, typ=typ)
        self._text_buffer.add_message(txt, time=time,
                nickname=nickname,
                highlight=highlight,
                nick_color=nick_color,
                history=history,
                user=forced_user,
                identifier=identifier,
                jid=jid)

    def modify_message(self, txt, old_id, new_id, user=None, jid=None, nickname=None):
        self.log_message(txt, nickname, typ=1)
        message = self._text_buffer.modify_message(txt, old_id, new_id, time=time, user=user, jid=jid)
        if message:
            self.text_win.modify_message(old_id, message)
            self.core.refresh_window()
            return True
        return False

    def last_words_completion(self):
        """
        Complete the input with words recently said
        """
        # build the list of the recent words
        char_we_dont_want = string.punctuation+' ’„“”…«»'
        words = list()
        for msg in self._text_buffer.messages[:-40:-1]:
            if not msg:
                continue
            txt = xhtml.clean_text(msg.txt)
            for char in char_we_dont_want:
                txt = txt.replace(char, ' ')
            for word in txt.split():
                if len(word) >= 4 and word not in words:
                    words.append(word)
        words.extend([word for word in config.get('words').split(':') if word])
        self.input.auto_completion(words, ' ', quotify=False)

    def on_enter(self):
        txt = self.input.key_enter()
        if txt:
            if not self.execute_command(txt):
                if txt.startswith('//'):
                    txt = txt[1:]
                self.command_say(xhtml.convert_simple_to_full_colors(txt))
        self.cancel_paused_delay()

    @command_args_parser.raw
    def command_xhtml(self, xhtml):
        """"
        /xhtml <custom xhtml>
        """
        message = self.generate_xhtml_message(xhtml)
        if message:
            message.send()

    def generate_xhtml_message(self, arg):
        if not arg:
            return
        try:
            body = xhtml.clean_text(xhtml.xhtml_to_poezio_colors(arg))
            ET.fromstring(arg)
        except:
            self.core.information('Could not send custom xhtml', 'Error')
            log.error('/xhtml: Unable to send custom xhtml', exc_info=True)
            return

        msg = self.core.xmpp.make_message(self.get_dest_jid())
        msg['body'] = body
        msg.enable('html')
        msg['html']['body'] = arg
        return msg

    def get_dest_jid(self):
        return self.name

    @refresh_wrapper.always
    def command_clear(self, ignored):
        """
        /clear
        """
        self._text_buffer.messages = []
        self.text_win.rebuild_everything(self._text_buffer)

    def send_chat_state(self, state, always_send=False):
        """
        Send an empty chatstate message
        """
        if not self.is_muc or self.joined:
            if state in ('active', 'inactive', 'gone') and self.inactive and not always_send:
                return
            if (config.get_by_tabname('send_chat_states', self.general_jid)
                    and self.remote_wants_chatstates is not False):
                msg = self.core.xmpp.make_message(self.get_dest_jid())
                msg['type'] = self.message_type
                msg['chat_state'] = state
                self.chat_state = state
                msg.send()
                return True

    def send_composing_chat_state(self, empty_after):
        """
        Send the "active" or "composing" chatstate, depending
        on the the current status of the input
        """
        name = self.general_jid
        if (config.get_by_tabname('send_chat_states', name)
                and self.remote_wants_chatstates):
            needed = 'inactive' if self.inactive else 'active'
            self.cancel_paused_delay()
            if not empty_after:
                if self.chat_state != "composing":
                    self.send_chat_state("composing")
                self.set_paused_delay(True)
            elif empty_after and self.chat_state != needed:
                self.send_chat_state(needed, True)

    def set_paused_delay(self, composing):
        """
        we create a timed event that will put us to paused
        in a few seconds
        """
        if not config.get_by_tabname('send_chat_states', self.general_jid):
            return
        # First, cancel the delay if it already exists, before rescheduling
        # it at a new date
        self.cancel_paused_delay()
        new_event = timed_events.DelayedEvent(4, self.send_chat_state, 'paused')
        self.core.add_timed_event(new_event)
        self.timed_event_paused = new_event

    def cancel_paused_delay(self):
        """
        Remove that event from the list and set it to None.
        Called for example when the input is emptied, or when the message
        is sent
        """
        if self.timed_event_paused is not None:
            self.core.remove_timed_event(self.timed_event_paused)
            self.timed_event_paused = None

    @command_args_parser.raw
    def command_correct(self, line):
        """
        /correct <fixed message>
        """
        if not line:
            self.core.command.help('correct')
            return
        if not self.last_sent_message:
            self.core.information('There is no message to correct.')
            return
        self.command_say(line, correct=True)

    def completion_correct(self, the_input):
        if self.last_sent_message and the_input.get_argument_position() == 1:
            return the_input.auto_completion([self.last_sent_message['body']], '', quotify=False)

    @property
    def inactive(self):
        """Whether we should send inactive or active as a chatstate"""
        return self.core.status.show in ('xa', 'away') or\
                (hasattr(self, 'directed_presence') and not self.directed_presence)

    def move_separator(self):
        self.text_win.remove_line_separator()
        self.text_win.add_line_separator(self._text_buffer)
        self.text_win.refresh()
        self.input.refresh()

    def get_conversation_messages(self):
        return self._text_buffer.messages

    def check_scrolled(self):
        if self.text_win.pos != 0:
            self.state = 'scrolled'

    @command_args_parser.raw
    def command_say(self, line, correct=False):
        pass

    def on_line_up(self):
        return self.text_win.scroll_up(1)

    def on_line_down(self):
        return self.text_win.scroll_down(1)

    def on_scroll_up(self):
        return self.text_win.scroll_up(self.text_win.height-1)

    def on_scroll_down(self):
        return self.text_win.scroll_down(self.text_win.height-1)

    def on_half_scroll_up(self):
        return self.text_win.scroll_up((self.text_win.height-1) // 2)

    def on_half_scroll_down(self):
        return self.text_win.scroll_down((self.text_win.height-1) // 2)

    @refresh_wrapper.always
    def scroll_separator(self):
        self.text_win.scroll_to_separator()

class OneToOneTab(ChatTab):

    def __init__(self, core, jid=''):
        ChatTab.__init__(self, core, jid)

        # Set to true once the first disco is done
        self.__initial_disco = False
        # change this to True or False when
        # we know that the remote user wants chatstates, or not.
        # None means we don’t know yet, and we send only "active" chatstates
        self._remote_wants_chatstates = None
        self.remote_supports_attention = True
        self.remote_supports_receipts = True
        self.check_features()

    @property
    def remote_wants_chatstates(self):
        return self._remote_wants_chatstates

    @remote_wants_chatstates.setter
    def remote_wants_chatstates(self, value):
        old_value = self._remote_wants_chatstates
        self._remote_wants_chatstates = value
        if (old_value is None and value != None) or \
                (old_value != value and value != None):
            ok = get_theme().CHAR_OK
            nope = get_theme().CHAR_EMPTY
            support = ok if value else nope
            if value:
                msg = '\x19%s}Contact supports chat states [%s].'
            else:
                msg = '\x19%s}Contact does not support chat states [%s].'
            color = dump_tuple(get_theme().COLOR_INFORMATION_TEXT)
            msg = msg % (color, support)
            self.add_message(msg, typ=0)
            self.core.refresh_window()

    def ack_message(self, msg_id, msg_jid):
        """
        Ack a message
        """
        new_msg = self._text_buffer.ack_message(msg_id, msg_jid)
        if new_msg:
            self.text_win.modify_message(msg_id, new_msg)
            self.core.refresh_window()

    def nack_message(self, error, msg_id, msg_jid):
        """
        Ack a message
        """
        new_msg = self._text_buffer.nack_message(error, msg_id, msg_jid)
        if new_msg:
            self.text_win.modify_message(msg_id, new_msg)
            self.core.refresh_window()
            return True
        return False

    @command_args_parser.raw
    def command_xhtml(self, xhtml_data):
        message = self.generate_xhtml_message(xhtml_data)
        if message:
            message['type'] = 'chat'
            if self.remote_supports_receipts:
                message._add_receipt = True
            if self.remote_wants_chatstates:
                message['chat_sate'] = 'active'
            message.send()
            body = xhtml.xhtml_to_poezio_colors(xhtml_data, force=True)
            self._text_buffer.add_message(body, nickname=self.core.own_nick,
                                          identifier=message['id'],)
            self.refresh()

    def check_features(self):
        "check the features supported by the other party"
        if safeJID(self.get_dest_jid()).resource:
            self.core.xmpp.plugin['xep_0030'].get_info(
                    jid=self.get_dest_jid(), timeout=5,
                    callback=self.features_checked)

    @command_args_parser.raw
    def command_attention(self, message):
        """/attention [message]"""
        if message is not '':
            self.command_say(message, attention=True)
        else:
            msg = self.core.xmpp.make_message(self.get_dest_jid())
            msg['type'] = 'chat'
            msg['attention'] = True
            msg.send()

    @command_args_parser.raw
    def command_say(self, line, correct=False, attention=False):
        pass

    def missing_command_callback(self, command_name):
        if command_name not in ('correct', 'attention'):
            return False

        if command_name == 'correct':
            feature = 'message correction'
        elif command_name == 'attention':
            feature = 'attention requests'
        msg = ('%s does not support %s, therefore the /%s '
               'command is currently disabled in this tab.')
        msg = msg % (self.name, feature, command_name)
        self.core.information(msg, 'Info')
        return True

    def _feature_attention(self, features):
        "Check for the 'attention' features"
        if 'urn:xmpp:attention:0' in features:
            self.remote_supports_attention = True
            self.register_command('attention', self.command_attention,
                                  usage='[message]',
                                  shortdesc='Request the attention.',
                                  desc='Attention: Request the attention of '
                                       'the contact. Can also send a message'
                                       ' along with the attention.')
        else:
            self.remote_supports_attention = False
        return self.remote_supports_attention

    def _feature_correct(self, features):
        "Check for the 'correction' feature"
        if not 'urn:xmpp:message-correct:0' in features:
            if 'correct' in self.commands:
                del self.commands['correct']
        elif not 'correct' in self.commands:
            self.register_command('correct', self.command_correct,
                    desc='Fix the last message with whatever you want.',
                    shortdesc='Correct the last message.',
                    completion=self.completion_correct)
        return 'correct' in self.commands

    def _feature_receipts(self, features):
        "Check for the 'receipts' feature"
        if 'urn:xmpp:receipts' in features:
            self.remote_supports_receipts = True
        else:
            self.remote_supports_receipts = False
        return self.remote_supports_receipts

    def features_checked(self, iq):
        "Features check callback"
        features = iq['disco_info'].get_features() or []
        before = ('correct' in self.commands,
                  self.remote_supports_attention,
                  self.remote_supports_receipts)
        correct = self._feature_correct(features)
        attention = self._feature_attention(features)
        receipts = self._feature_receipts(features)

        if (correct, attention, receipts) == before and self.__initial_disco:
            return
        else:
            self.__initial_disco = True

        if not (correct or attention or receipts):
            return # don’t display anything

        ok = get_theme().CHAR_OK
        nope = get_theme().CHAR_EMPTY

        correct = ok if correct else nope
        attention = ok if attention else nope
        receipts = ok if receipts else nope

        msg = ('\x19%s}Contact supports: correction [%s], '
               'attention [%s], receipts [%s].')
        color = dump_tuple(get_theme().COLOR_INFORMATION_TEXT)
        msg = msg % (color, correct, attention, receipts)
        self.add_message(msg, typ=0)
        self.core.refresh_window()

