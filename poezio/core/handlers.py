"""
XMPP-related handlers for the Core class
"""

import logging
log = logging.getLogger(__name__)

import asyncio
import curses
import functools
import ssl
import sys
import time
from datetime import datetime
from hashlib import sha1, sha512
from os import path

from slixmpp import InvalidJID
from slixmpp.xmlstream.stanzabase import StanzaBase, ElementBase
from xml.etree import ElementTree as ET

from poezio import common
from poezio import fixes
from poezio import pep
from poezio import tabs
from poezio import windows
from poezio import xhtml
from poezio import multiuserchat as muc
from poezio.common import safeJID
from poezio.config import config, CACHE_DIR
from poezio.contact import Resource
from poezio.logger import logger
from poezio.roster import roster
from poezio.text_buffer import CorrectionError, AckError
from poezio.theming import dump_tuple, get_theme

from poezio.core.commands import dumb_callback

try:
    from pygments import highlight
    from pygments.lexers import get_lexer_by_name
    from pygments.formatters import HtmlFormatter
    LEXER = get_lexer_by_name('xml')
    FORMATTER = HtmlFormatter(noclasses=True)
    PYGMENTS = True
except ImportError:
    PYGMENTS = False


class HandlerCore:
    def __init__(self, core):
        self.core = core

    def on_session_start_features(self, _):
        """
        Enable carbons & blocking on session start if wanted and possible
        """
        def callback(iq):
            if not iq:
                return
            features = iq['disco_info']['features']
            rostertab = self.core.get_tab_by_name('Roster', tabs.RosterInfoTab)
            rostertab.check_blocking(features)
            rostertab.check_saslexternal(features)
            if (config.get('enable_carbons') and
                    'urn:xmpp:carbons:2' in features):
                self.core.xmpp.plugin['xep_0280'].enable()
            self.core.check_bookmark_storage(features)

        self.core.xmpp.plugin['xep_0030'].get_info(jid=self.core.xmpp.boundjid.domain,
                                                   callback=callback)

        self.key = config.get('key')
        if self.key:
            self.key = self.key.encode('utf-8')

            # apply padding
            length = 32 - (len(self.key) % 32)
            self.key += bytes([length]) * length

    def on_carbon_received(self, message):
        """
        Carbon <received/> received
        """
        def ignore_message(recv):
            log.debug('%s has category conference, ignoring carbon',
                      recv['from'].server)
        def receive_message(recv):
            recv['to'] = self.core.xmpp.boundjid.full
            if recv['receipt']:
                return self.on_receipt(recv)
            self.on_normal_message(recv)

        recv = message['carbon_received']
        if (recv['from'].bare not in roster or
            roster[recv['from'].bare].subscription == 'none'):
            fixes.has_identity(self.core.xmpp, recv['from'].server,
                               identity='conference',
                               on_true=functools.partial(ignore_message, recv),
                               on_false=functools.partial(receive_message, recv))
            return
        else:
            receive_message(recv)

    def on_carbon_sent(self, message):
        """
        Carbon <sent/> received
        """
        def ignore_message(sent):
            log.debug('%s has category conference, ignoring carbon',
                      sent['to'].server)
        def send_message(sent):
            sent['from'] = self.core.xmpp.boundjid.full
            self.on_normal_message(sent)

        sent = message['carbon_sent']
        if (sent['to'].bare not in roster or
                roster[sent['to'].bare].subscription == 'none'):
            fixes.has_identity(self.core.xmpp, sent['to'].server,
                               identity='conference',
                               on_true=functools.partial(ignore_message, sent),
                               on_false=functools.partial(send_message, sent))
        else:
            send_message(sent)

    ### Invites ###

    def on_groupchat_invitation(self, message):
        """
        Mediated invitation received
        """
        jid = message['from']
        if jid.bare in self.core.pending_invites:
            return
        # there are 2 'x' tags in the messages, making message['x'] useless
        invite = StanzaBase(self.core.xmpp, xml=message.find('{http://jabber.org/protocol/muc#user}x/{http://jabber.org/protocol/muc#user}invite'))
        inviter = invite['from']
        reason = invite['reason']
        password = invite['password']
        msg = "You are invited to the room %s by %s" % (jid.full, inviter.full)
        if reason:
            msg += "because: %s" % reason
        if password:
            msg += ". The password is \"%s\"." % password
        self.core.information(msg, 'Info')
        if 'invite' in config.get('beep_on').split():
            curses.beep()
        logger.log_roster_change(inviter.full, 'invited you to %s' % jid.full)
        self.core.pending_invites[jid.bare] = inviter.full

    def on_groupchat_decline(self, decline):
        "Mediated invitation declined; skip for now"
        pass

    def on_groupchat_direct_invitation(self, message):
        """
        Direct invitation received
        """
        room = safeJID(message['groupchat_invite']['jid'])
        if room.bare in self.core.pending_invites:
            return

        inviter = message['from']
        reason = message['groupchat_invite']['reason']
        password = message['groupchat_invite']['password']
        continue_ = message['groupchat_invite']['continue']
        msg = "You are invited to the room %s by %s" % (room, inviter.full)

        if password:
            msg += ' (password: "%s")' % password
        if continue_:
            msg += '\nto continue the discussion'
        if reason:
            msg += "\nreason: %s" % reason

        self.core.information(msg, 'Info')
        if 'invite' in config.get('beep_on').split():
            curses.beep()

        self.core.pending_invites[room.bare] = inviter.full
        logger.log_roster_change(inviter.full, 'invited you to %s' % room.bare)

    ### "classic" messages ###

    def on_message(self, message):
        """
        When receiving private message from a muc OR a normal message
        (from one of our contacts)
        """
        if message.find('{http://jabber.org/protocol/muc#user}x/{http://jabber.org/protocol/muc#user}invite') != None:
            return
        if message['type'] == 'groupchat':
            return
        # Differentiate both type of messages, and call the appropriate handler.
        jid_from = message['from']
        for tab in self.core.get_tabs(tabs.MucTab):
            if tab.name == jid_from.bare:
                if message['type'] == 'chat':
                    self.on_groupchat_private_message(message)
                    return
        self.on_normal_message(message)

    def on_error_message(self, message):
        """
        When receiving any message with type="error"
        """
        jid_from = message['from']
        for tab in self.core.get_tabs(tabs.MucTab):
            if tab.name == jid_from.bare:
                if message['type'] == 'error':
                    self.core.room_error(message, jid_from.bare)
                else:
                    self.on_groupchat_private_message(message)
                return
        tab = self.core.get_conversation_by_jid(message['from'], create=False)
        error_msg = self.core.get_error_message(message, deprecated=True)
        if not tab:
            self.core.information(error_msg, 'Error')
            return
        error = '\x19%s}%s\x19o' % (dump_tuple(get_theme().COLOR_CHAR_NACK),
                                      error_msg)
        if not tab.nack_message('\n' + error, message['id'], message['to']):
            tab.add_message(error, typ=0)
            self.core.refresh_window()


    def on_normal_message(self, message):
        """
        When receiving "normal" messages (not a private message from a
        muc participant)
        """
        if message['type'] == 'error':
            return
        elif message['type'] == 'headline' and message['body']:
            return self.core.information('%s says: %s' % (message['from'], message['body']), 'Headline')

        use_xhtml = config.get('enable_xhtml_im')
        tmp_dir = config.get('tmp_image_dir') or path.join(CACHE_DIR, 'images')
        extract_images = config.get('extract_inline_images')
        body = xhtml.get_body_from_message_stanza(message, use_xhtml=use_xhtml,
                                                  tmp_dir=tmp_dir,
                                                  extract_images=extract_images)
        if not body:
            return

        remote_nick = ''
        # normal message, we are the recipient
        if message['to'].bare == self.core.xmpp.boundjid.bare:
            conv_jid = message['from']
            jid = conv_jid
            color = get_theme().COLOR_REMOTE_USER
            # check for a name
            if conv_jid.bare in roster:
                remote_nick = roster[conv_jid.bare].name
            # check for a received nick
            if not remote_nick and config.get('enable_user_nick'):
                if message.xml.find('{http://jabber.org/protocol/nick}nick') is not None:
                    remote_nick = message['nick']['nick']
            if not remote_nick:
                remote_nick = conv_jid.user
                if not remote_nick:
                    remote_nick = conv_jid.full
            own = False
        # we wrote the message (happens with carbons)
        elif message['from'].bare == self.core.xmpp.boundjid.bare:
            conv_jid = message['to']
            jid = self.core.xmpp.boundjid
            color = get_theme().COLOR_OWN_NICK
            remote_nick = self.core.own_nick
            own = True
        # we are not part of that message, drop it
        else:
            return

        conversation = self.core.get_conversation_by_jid(conv_jid, create=True)
        if isinstance(conversation, tabs.DynamicConversationTab) and conv_jid.resource:
            conversation.lock(conv_jid.resource)

        if not own and not conversation.nick:
            conversation.nick = remote_nick
        elif not own: # keep a fixed nick during the whole conversation
            remote_nick = conversation.nick

        self.core.events.trigger('conversation_msg', message, conversation)
        if not message['body']:
            return
        body = xhtml.get_body_from_message_stanza(message, use_xhtml=use_xhtml,
                                                  tmp_dir=tmp_dir,
                                                  extract_images=extract_images)
        delayed, date = common.find_delayed_tag(message)

        def try_modify():
            replaced_id = message['replace']['id']
            if replaced_id and config.get_by_tabname('group_corrections',
                                                     conv_jid.bare):
                try:
                    conversation.modify_message(body, replaced_id, message['id'], jid=jid,
                            nickname=remote_nick)
                    return True
                except CorrectionError:
                    log.debug('Unable to correct a message', exc_info=True)
            return False

        if not try_modify():
            conversation.add_message(body, date,
                    nickname=remote_nick,
                    nick_color=color,
                    history=delayed,
                    identifier=message['id'],
                    jid=jid,
                    typ=1)

        if conversation.remote_wants_chatstates is None and not delayed:
            if message['chat_state']:
                conversation.remote_wants_chatstates = True
            else:
                conversation.remote_wants_chatstates = False
        if not own and 'private' in config.get('beep_on').split():
            if not config.get_by_tabname('disable_beep', conv_jid.bare):
                curses.beep()
        if self.core.current_tab() is not conversation:
            if not own:
                conversation.state = 'private'
                self.core.refresh_tab_win()
            else:
                conversation.set_state('normal')
                self.core.refresh_tab_win()
        else:
            self.core.refresh_window()

    def on_nick_received(self, message):
        """
        Called when a pep notification for an user nickname
        is received
        """
        contact = roster[message['from'].bare]
        if not contact:
            return
        item = message['pubsub_event']['items']['item']
        if item.xml.find('{http://jabber.org/protocol/nick}nick'):
            contact.name = item['nick']['nick']
        else:
            contact.name = ''

    def on_gaming_event(self, message):
        """
        Called when a pep notification for user gaming
        is received
        """
        contact = roster[message['from'].bare]
        if not contact:
            return
        item = message['pubsub_event']['items']['item']
        old_gaming = contact.gaming
        if item.xml.find('{urn:xmpp:gaming:0}gaming'):
            item = item['gaming']
            # only name and server_address are used for now
            contact.gaming = {
                    'character_name': item['character_name'],
                    'character_profile': item['character_profile'],
                    'name': item['name'],
                    'level': item['level'],
                    'uri': item['uri'],
                    'server_name': item['server_name'],
                    'server_address': item['server_address'],
                }
        else:
            contact.gaming = {}

        if contact.gaming:
            logger.log_roster_change(contact.bare_jid, 'is playing %s' % (common.format_gaming_string(contact.gaming)))

        if old_gaming != contact.gaming and config.get_by_tabname('display_gaming_notifications', contact.bare_jid):
            if contact.gaming:
                self.core.information('%s is playing %s' % (contact.bare_jid, common.format_gaming_string(contact.gaming)), 'Gaming')
            else:
                self.core.information(contact.bare_jid + ' stopped playing.', 'Gaming')

    def on_mood_event(self, message):
        """
        Called when a pep notification for an user mood
        is received.
        """
        contact = roster[message['from'].bare]
        if not contact:
            return
        roster.modified()
        item = message['pubsub_event']['items']['item']
        old_mood = contact.mood
        if item.xml.find('{http://jabber.org/protocol/mood}mood'):
            mood = item['mood']['value']
            if mood:
                mood = pep.MOODS.get(mood, mood)
                text = item['mood']['text']
                if text:
                    mood = '%s (%s)' % (mood, text)
                contact.mood = mood
            else:
                contact.mood = ''
        else:
            contact.mood = ''

        if contact.mood:
            logger.log_roster_change(contact.bare_jid, 'has now the mood: %s' % contact.mood)

        if old_mood != contact.mood and config.get_by_tabname('display_mood_notifications', contact.bare_jid):
            if contact.mood:
                self.core.information('Mood from '+ contact.bare_jid + ': ' + contact.mood, 'Mood')
            else:
                self.core.information(contact.bare_jid + ' stopped having his/her mood.', 'Mood')

    def on_activity_event(self, message):
        """
        Called when a pep notification for an user activity
        is received.
        """
        contact = roster[message['from'].bare]
        if not contact:
            return
        roster.modified()
        item = message['pubsub_event']['items']['item']
        old_activity = contact.activity
        if item.xml.find('{http://jabber.org/protocol/activity}activity'):
            try:
                activity = item['activity']['value']
            except ValueError:
                return
            if activity[0]:
                general = pep.ACTIVITIES.get(activity[0])
                s = general['category']
                if activity[1]:
                    s = s + '/' + general.get(activity[1], 'other')
                text = item['activity']['text']
                if text:
                    s = '%s (%s)' % (s, text)
                contact.activity = s
            else:
                contact.activity = ''
        else:
            contact.activity = ''

        if contact.activity:
            logger.log_roster_change(contact.bare_jid, 'has now the activity %s' % contact.activity)

        if old_activity != contact.activity and config.get_by_tabname('display_activity_notifications', contact.bare_jid):
            if contact.activity:
                self.core.information('Activity from '+ contact.bare_jid + ': ' + contact.activity, 'Activity')
            else:
                self.core.information(contact.bare_jid + ' stopped doing his/her activity.', 'Activity')

    def on_tune_event(self, message):
        """
        Called when a pep notification for an user tune
        is received
        """
        contact = roster[message['from'].bare]
        if not contact:
            return
        roster.modified()
        item = message['pubsub_event']['items']['item']
        old_tune = contact.tune
        if item.xml.find('{http://jabber.org/protocol/tune}tune'):
            item = item['tune']
            contact.tune = {
                    'artist': item['artist'],
                    'length': item['length'],
                    'rating': item['rating'],
                    'source': item['source'],
                    'title': item['title'],
                    'track': item['track'],
                    'uri': item['uri']
                }
        else:
            contact.tune = {}

        if contact.tune:
            logger.log_roster_change(message['from'].bare, 'is now listening to %s' % common.format_tune_string(contact.tune))

        if old_tune != contact.tune and config.get_by_tabname('display_tune_notifications', contact.bare_jid):
            if contact.tune:
                self.core.information(
                        'Tune from '+ message['from'].bare + ': ' + common.format_tune_string(contact.tune),
                        'Tune')
            else:
                self.core.information(contact.bare_jid + ' stopped listening to music.', 'Tune')

    def on_groupchat_message(self, message):
        """
        Triggered whenever a message is received from a multi-user chat room.
        """
        if message['subject']:
            return
        room_from = message['from'].bare

        if message['type'] == 'error': # Check if it's an error
            self.core.room_error(message, room_from)
            return

        tab = self.core.get_tab_by_name(room_from, tabs.MucTab)
        if not tab:
            self.core.information("message received for a non-existing room: %s" % (room_from))
            muc.leave_groupchat(self.core.xmpp, room_from, self.core.own_nick, msg='')
            return

        nick_from = message['mucnick']
        user = tab.get_user_by_name(nick_from)
        if user and user in tab.ignores:
            return

        self.core.events.trigger('muc_msg', message, tab)
        use_xhtml = config.get('enable_xhtml_im')
        tmp_dir = config.get('tmp_image_dir') or path.join(CACHE_DIR, 'images')
        extract_images = config.get('extract_inline_images')
        body = xhtml.get_body_from_message_stanza(message, use_xhtml=use_xhtml,
                                                  tmp_dir=tmp_dir,
                                                  extract_images=extract_images,
                                                  key=self.key)
        if not body:
            return

        enc_type = xhtml.get_message_enc_type(message)
        if enc_type == "stealth":
            nick_from = "%s $" % nick_from
        elif enc_type == "gold":
            nick_from = "%s #" % nick_from

        old_state = tab.state
        delayed, date = common.find_delayed_tag(message)
        replaced_id = message['replace']['id']
        replaced = False
        if replaced_id is not '' and config.get_by_tabname('group_corrections',
                                                           message['from'].bare):
            try:
                delayed_date = date or datetime.now()
                if tab.modify_message(body, replaced_id, message['id'],
                        time=delayed_date,
                        nickname=nick_from, user=user):
                    self.core.events.trigger('highlight', message, tab)
                replaced = True
            except CorrectionError:
                log.debug('Unable to correct a message', exc_info=True)
        if not replaced and tab.add_message(body, date, nick_from, history=delayed, identifier=message['id'], jid=message['from'], typ=1):
            self.core.events.trigger('highlight', message, tab)

        if message['from'].resource == tab.own_nick:
            tab.last_sent_message = message

        if tab is self.core.current_tab():
            tab.text_win.refresh()
            tab.info_header.refresh(tab, tab.text_win, user=tab.own_user)
            tab.input.refresh()
            self.core.doupdate()
        elif tab.state != old_state:
            self.core.refresh_tab_win()
            current = self.core.current_tab()
            if hasattr(current, 'input') and current.input:
                current.input.refresh()
            self.core.doupdate()

        if 'message' in config.get('beep_on').split():
            if (not config.get_by_tabname('disable_beep', room_from)
                    and self.core.own_nick != message['from'].resource):
                curses.beep()

    def on_muc_own_nickchange(self, muc):
        "We changed our nick in a MUC"
        for tab in self.core.get_tabs(tabs.PrivateTab):
            if tab.parent_muc == muc:
                tab.own_nick = muc.own_nick

    def on_groupchat_private_message(self, message):
        """
        We received a Private Message (from someone in a Muc)
        """
        jid = message['from']
        nick_from = jid.resource
        if not nick_from:
            self.on_groupchat_message(message)
            return

        room_from = jid.bare
        use_xhtml = config.get('enable_xhtml_im')
        tmp_dir = config.get('tmp_image_dir') or path.join(CACHE_DIR, 'images')
        extract_images = config.get('extract_inline_images')
        body = xhtml.get_body_from_message_stanza(message, use_xhtml=use_xhtml,
                                                  tmp_dir=tmp_dir,
                                                  extract_images=extract_images)
        tab = self.core.get_tab_by_name(jid.full, tabs.PrivateTab) # get the tab with the private conversation
        ignore = config.get_by_tabname('ignore_private', room_from)
        if not tab: # It's the first message we receive: create the tab
            if body and not ignore:
                tab = self.core.open_private_window(room_from, nick_from, False)
        if ignore:
            self.core.events.trigger('ignored_private', message, tab)
            msg = config.get_by_tabname('private_auto_response', room_from)
            if msg and body:
                self.core.xmpp.send_message(mto=jid.full, mbody=msg, mtype='chat')
            return
        self.core.events.trigger('private_msg', message, tab)
        body = xhtml.get_body_from_message_stanza(message, use_xhtml=use_xhtml,
                                                  tmp_dir=tmp_dir,
                                                  extract_images=extract_images)
        if not body or not tab:
            return
        replaced_id = message['replace']['id']
        replaced = False
        user = tab.parent_muc.get_user_by_name(nick_from)
        if replaced_id is not '' and config.get_by_tabname('group_corrections',
                                                           room_from):
            try:
                tab.modify_message(body, replaced_id, message['id'], user=user, jid=message['from'],
                        nickname=nick_from)
                replaced = True
            except CorrectionError:
                log.debug('Unable to correct a message', exc_info=True)
        if not replaced:
            tab.add_message(body, time=None, nickname=nick_from,
                            forced_user=user,
                            identifier=message['id'],
                            jid=message['from'],
                            typ=1)

        if tab.remote_wants_chatstates is None:
            if message['chat_state']:
                tab.remote_wants_chatstates = True
            else:
                tab.remote_wants_chatstates = False
        if 'private' in config.get('beep_on').split():
            if not config.get_by_tabname('disable_beep', jid.full):
                curses.beep()
        if tab is self.core.current_tab():
            self.core.refresh_window()
        else:
            tab.state = 'private'
            self.core.refresh_tab_win()

    ### Chatstates ###

    def on_chatstate_active(self, message):
        self._on_chatstate(message, "active")

    def on_chatstate_inactive(self, message):
        self._on_chatstate(message, "inactive")

    def on_chatstate_composing(self, message):
        self._on_chatstate(message, "composing")

    def on_chatstate_paused(self, message):
        self._on_chatstate(message, "paused")

    def on_chatstate_gone(self, message):
        self._on_chatstate(message, "gone")

    def _on_chatstate(self, message, state):
        if message['type'] == 'chat':
            if not self._on_chatstate_normal_conversation(message, state):
                tab = self.core.get_tab_by_name(message['from'].full, tabs.PrivateTab)
                if not tab:
                    return
                self._on_chatstate_private_conversation(message, state)
        elif message['type'] == 'groupchat':
            self.on_chatstate_groupchat_conversation(message, state)

    def _on_chatstate_normal_conversation(self, message, state):
        tab = self.core.get_conversation_by_jid(message['from'], False)
        if not tab:
            return False
        tab.remote_wants_chatstates = True
        self.core.events.trigger('normal_chatstate', message, tab)
        tab.chatstate = state
        if state == 'gone' and isinstance(tab, tabs.DynamicConversationTab):
            tab.unlock()
        if tab == self.core.current_tab():
            tab.refresh_info_header()
            self.core.doupdate()
        else:
            _composing_tab_state(tab, state)
            self.core.refresh_tab_win()
        return True

    def _on_chatstate_private_conversation(self, message, state):
        """
        Chatstate received in a private conversation from a MUC
        """
        tab = self.core.get_tab_by_name(message['from'].full, tabs.PrivateTab)
        if not tab:
            return
        tab.remote_wants_chatstates = True
        self.core.events.trigger('private_chatstate', message, tab)
        tab.chatstate = state
        if tab == self.core.current_tab():
            tab.refresh_info_header()
            self.core.doupdate()
        else:
            _composing_tab_state(tab, state)
            self.core.refresh_tab_win()

    def on_chatstate_groupchat_conversation(self, message, state):
        """
        Chatstate received in a MUC
        """
        nick = message['mucnick']
        room_from = message.get_mucroom()
        tab = self.core.get_tab_by_name(room_from, tabs.MucTab)
        if tab and tab.get_user_by_name(nick):
            self.core.events.trigger('muc_chatstate', message, tab)
            tab.get_user_by_name(nick).chatstate = state
        if tab == self.core.current_tab():
            if not self.core.size.tab_degrade_x:
                tab.user_win.refresh(tab.users)
            tab.input.refresh()
            self.core.doupdate()
        else:
            _composing_tab_state(tab, state)
            self.core.refresh_tab_win()

    ### subscription-related handlers ###

    def on_roster_update(self, iq):
        """
        The roster was received.
        """
        for item in iq['roster']:
            try:
                jid = item['jid']
            except InvalidJID:
                jid = item._get_attr('jid', '')
                log.error('Invalid JID: "%s"', jid, exc_info=True)
            else:
                if item['subscription'] == 'remove':
                    del roster[jid]
                else:
                    roster.update_contact_groups(jid)
        roster.update_size()
        if isinstance(self.core.current_tab(), tabs.RosterInfoTab):
            self.core.refresh_window()

    def on_subscription_request(self, presence):
        """subscribe received"""
        jid = presence['from'].bare
        contact = roster[jid]
        if contact and contact.subscription in ('from', 'both'):
            return
        elif contact and contact.subscription == 'to':
            self.core.xmpp.sendPresence(pto=jid, ptype='subscribed')
            self.core.xmpp.sendPresence(pto=jid)
        else:
            if not contact:
                contact = roster.get_and_set(jid)
            roster.update_contact_groups(contact)
            contact.pending_in = True
            self.core.information('%s wants to subscribe to your presence, use '
                                  '/accept <jid> or /deny <jid> in the roster '
                                  'tab to accept or reject the query.' % jid,
                                  'Roster')
            self.core.get_tab_by_number(0).state = 'highlight'
            roster.modified()
        if isinstance(self.core.current_tab(), tabs.RosterInfoTab):
            self.core.refresh_window()

    def on_subscription_authorized(self, presence):
        """subscribed received"""
        jid = presence['from'].bare
        contact = roster[jid]
        if contact.subscription not in ('both', 'from'):
            self.core.information('%s accepted your contact proposal' % jid, 'Roster')
        if contact.pending_out:
            contact.pending_out = False

        roster.modified()

        if isinstance(self.core.current_tab(), tabs.RosterInfoTab):
            self.core.refresh_window()

    def on_subscription_remove(self, presence):
        """unsubscribe received"""
        jid = presence['from'].bare
        contact = roster[jid]
        if not contact:
            return
        roster.modified()
        self.core.information('%s does not want to receive your status anymore.' % jid, 'Roster')
        self.core.get_tab_by_number(0).state = 'highlight'
        if isinstance(self.core.current_tab(), tabs.RosterInfoTab):
            self.core.refresh_window()

    def on_subscription_removed(self, presence):
        """unsubscribed received"""
        jid = presence['from'].bare
        contact = roster[jid]
        if not contact:
            return
        roster.modified()
        if contact.pending_out:
            self.core.information('%s rejected your contact proposal' % jid, 'Roster')
            contact.pending_out = False
        else:
            self.core.information('%s does not want you to receive his/her/its status anymore.'%jid, 'Roster')
        self.core.get_tab_by_number(0).state = 'highlight'
        if isinstance(self.core.current_tab(), tabs.RosterInfoTab):
            self.core.refresh_window()

    ### Presence-related handlers ###

    def on_presence(self, presence):
        if presence.match('presence/muc') or presence.xml.find('{http://jabber.org/protocol/muc#user}x'):
            return
        jid = presence['from']
        contact = roster[jid.bare]
        tab = self.core.get_conversation_by_jid(jid, create=False)
        if isinstance(tab, tabs.DynamicConversationTab):
            if tab.get_dest_jid() != jid.full:
                tab.unlock(from_=jid.full)
            elif presence['type'] == 'unavailable':
                tab.unlock()
        if contact is None:
            return
        roster.modified()
        contact.error = None
        self.core.events.trigger('normal_presence', presence, contact[jid.full])
        tab = self.core.get_conversation_by_jid(jid, create=False)
        if isinstance(self.core.current_tab(), tabs.RosterInfoTab):
            self.core.refresh_window()
        elif self.core.current_tab() == tab:
            tab.refresh()
            self.core.doupdate()

    def on_presence_error(self, presence):
        jid = presence['from']
        contact = roster[jid.bare]
        if not contact:
            return
        roster.modified()
        contact.error = presence['error']['type'] + ': ' + presence['error']['condition']
        # reset chat states status on presence error
        tab = self.core.get_tab_by_name(jid.full, tabs.ConversationTab)
        if tab:
            tab.remote_wants_chatstates = None

    def on_got_offline(self, presence):
        """
        A JID got offline
        """
        if presence.match('presence/muc') or presence.xml.find('{http://jabber.org/protocol/muc#user}x'):
            return
        jid = presence['from']
        if not logger.log_roster_change(jid.bare, 'got offline'):
            self.core.information('Unable to write in the log file', 'Error')
        # If a resource got offline, display the message in the conversation with this
        # precise resource.
        contact = roster[jid.bare]
        name = jid.bare
        if contact:
            roster.connected -= 1
            if contact.name:
                name = contact.name
        if jid.resource:
            self.core.add_information_message_to_conversation_tab(jid.full, '\x195}%s is \x191}offline' % name)
        self.core.add_information_message_to_conversation_tab(jid.bare, '\x195}%s is \x191}offline' % name)
        self.core.information('\x193}%s \x195}is \x191}offline' % name, 'Roster')
        roster.modified()
        if isinstance(self.core.current_tab(), tabs.RosterInfoTab):
            self.core.refresh_window()

    def on_got_online(self, presence):
        """
        A JID got online
        """
        if presence.match('presence/muc') or presence.xml.find('{http://jabber.org/protocol/muc#user}x'):
            return
        jid = presence['from']
        contact = roster[jid.bare]
        if contact is None:
            # Todo, handle presence coming from contacts not in roster
            return
        roster.connected += 1
        roster.modified()
        if not logger.log_roster_change(jid.bare, 'got online'):
            self.core.information('Unable to write in the log file', 'Error')
        resource = Resource(jid.full, {
            'priority': presence.get_priority() or 0,
            'status': presence['status'],
            'show': presence['show'],
            })
        self.core.events.trigger('normal_presence', presence, resource)
        name = contact.name if contact.name else jid.bare
        self.core.add_information_message_to_conversation_tab(jid.full, '\x195}%s is \x194}online' % name)
        if time.time() - self.core.connection_time > 10:
            # We do not display messages if we recently logged in
            if presence['status']:
                self.core.information("\x193}%s \x195}is \x194}online\x195} (\x19o%s\x195})" % (name, presence['status']), "Roster")
            else:
                self.core.information("\x193}%s \x195}is \x194}online\x195}" % name, "Roster")
            self.core.add_information_message_to_conversation_tab(jid.bare, '\x195}%s is \x194}online' % name)
        if isinstance(self.core.current_tab(), tabs.RosterInfoTab):
            self.core.refresh_window()

    def on_groupchat_presence(self, presence):
        """
        Triggered whenever a presence stanza is received from a user in a multi-user chat room.
        Display the presence on the room window and update the
        presence information of the concerned user
        """
        from_room = presence['from'].bare
        tab = self.core.get_tab_by_name(from_room, tabs.MucTab)
        if tab:
            self.core.events.trigger('muc_presence', presence, tab)
            tab.handle_presence(presence)


    ### Connection-related handlers ###

    def on_failed_connection(self, error):
        """
        We cannot contact the remote server
        """
        self.core.information("Connection to remote server failed: %s" % (error,), 'Error')

    def on_disconnected(self, event):
        """
        When we are disconnected from remote server
        """
        roster.connected = 0
        # Stop the ping plugin. It would try to send stanza on regular basis
        self.core.xmpp.plugin['xep_0199'].disable_keepalive()
        roster.modified()
        for tab in self.core.get_tabs(tabs.MucTab):
            tab.disconnect()
        msg_typ = 'Error' if not self.core.legitimate_disconnect else 'Info'
        self.core.information("Disconnected from server.", msg_typ)
        if not self.core.legitimate_disconnect and config.get('auto_reconnect', True):
            self.core.information("Auto-reconnecting.", 'Info')
            self.core.xmpp.start()

    def on_stream_error(self, event):
        """
        When we receive a stream error
        """
        if event and event['text']:
            self.core.information('Stream error: %s' % event['text'], 'Error')

    def on_failed_all_auth(self, event):
        """
        Authentication failed
        """
        self.core.information("Authentication failed (bad credentials?).",
                              'Error')
        self.core.legitimate_disconnect = True

    def on_no_auth(self, event):
        """
        Authentication failed (no mech)
        """
        self.core.information("Authentication failed, no login method available.",
                              'Error')
        self.core.legitimate_disconnect = True

    def on_connected(self, event):
        """
        Remote host responded, but we are not yet authenticated
        """
        self.core.information("Connected to server.", 'Info')

    def on_connecting(self, event):
        """
        Just before we try to connect to the server
        """
        self.core.legitimate_disconnect = False

    def on_session_start(self, event):
        """
        Called when we are connected and authenticated
        """
        self.core.connection_time = time.time()
        if not self.core.plugins_autoloaded: # Do not reload plugins on reconnection
            self.core.autoload_plugins()
        self.core.information("Authentication success.", 'Info')
        self.core.information("Your JID is %s" % self.core.xmpp.boundjid.full, 'Info')
        if not self.core.xmpp.anon:
            # request the roster
            self.core.xmpp.get_roster()
            roster.update_contact_groups(self.core.xmpp.boundjid.bare)
            # send initial presence
            if config.get('send_initial_presence'):
                pres = self.core.xmpp.make_presence()
                pres['show'] = self.core.status.show
                pres['status'] = self.core.status.message
                self.core.events.trigger('send_normal_presence', pres)
                pres.send()
        self.core.bookmarks.get_local()
        # join all the available bookmarks. As of yet, this is just the local ones
        self.core.join_initial_rooms(self.core.bookmarks)

        if config.get('enable_user_nick'):
            self.core.xmpp.plugin['xep_0172'].publish_nick(nick=self.core.own_nick, callback=dumb_callback)
        asyncio.async(self.core.xmpp.plugin['xep_0115'].update_caps())
        # Start the ping's plugin regular event
        self.core.xmpp.set_keepalive_values()

    ### Other handlers ###

    def on_status_codes(self, message):
        """
        Handle groupchat messages with status codes.
        Those are received when a room configuration change occurs.
        """
        room_from = message['from']
        tab = self.core.get_tab_by_name(room_from, tabs.MucTab)
        status_codes = set([s.attrib['code'] for s in message.findall('{%s}x/{%s}status' % (tabs.NS_MUC_USER, tabs.NS_MUC_USER))])
        if '101' in status_codes:
            self.core.information('Your affiliation in the room %s changed' % room_from, 'Info')
        elif tab and status_codes:
            show_unavailable = '102' in status_codes
            hide_unavailable = '103' in status_codes
            non_priv = '104' in status_codes
            logging_on = '170' in status_codes
            logging_off = '171' in status_codes
            non_anon = '172' in status_codes
            semi_anon = '173' in status_codes
            full_anon = '174' in status_codes
            modif = False
            if show_unavailable or hide_unavailable or non_priv or logging_off\
                    or non_anon or semi_anon or full_anon:
                tab.add_message('\x19%(info_col)s}Info: A configuration change not privacy-related occured.' %
                        {'info_col': dump_tuple(get_theme().COLOR_INFORMATION_TEXT)},
                        typ=2)
                modif = True
            if show_unavailable:
                tab.add_message('\x19%(info_col)s}Info: The unavailable members are now shown.' %
                        {'info_col': dump_tuple(get_theme().COLOR_INFORMATION_TEXT)},
                        typ=2)
            elif hide_unavailable:
                tab.add_message('\x19%(info_col)s}Info: The unavailable members are now hidden.' %
                        {'info_col': dump_tuple(get_theme().COLOR_INFORMATION_TEXT)},
                        typ=2)
            if non_anon:
                tab.add_message('\x191}Warning:\x19%(info_col)s} The room is now not anonymous. (public JID)' %
                        {'info_col': dump_tuple(get_theme().COLOR_INFORMATION_TEXT)},
                        typ=2)
            elif semi_anon:
                tab.add_message('\x19%(info_col)s}Info: The room is now semi-anonymous. (moderators-only JID)' %
                        {'info_col': dump_tuple(get_theme().COLOR_INFORMATION_TEXT)},
                        typ=2)
            elif full_anon:
                tab.add_message('\x19%(info_col)s}Info: The room is now fully anonymous.' %
                        {'info_col': dump_tuple(get_theme().COLOR_INFORMATION_TEXT)},
                        typ=2)
            if logging_on:
                tab.add_message('\x191}Warning: \x19%(info_col)s}This room is publicly logged' %
                        {'info_col': dump_tuple(get_theme().COLOR_INFORMATION_TEXT)},
                        typ=2)
            elif logging_off:
                tab.add_message('\x19%(info_col)s}Info: This room is not logged anymore.' %
                        {'info_col': dump_tuple(get_theme().COLOR_INFORMATION_TEXT)},
                        typ=2)
            if modif:
                self.core.refresh_window()

    def on_groupchat_subject(self, message):
        """
        Triggered when the topic is changed.
        """
        nick_from = message['mucnick']
        room_from = message.get_mucroom()
        tab = self.core.get_tab_by_name(room_from, tabs.MucTab)
        subject = message['subject']
        if subject is None or not tab:
            return
        if subject != tab.topic:
            # Do not display the message if the subject did not change or if we
            # receive an empty topic when joining the room.
            fmt = {
                'info_col': dump_tuple(get_theme().COLOR_INFORMATION_TEXT),
                'text_col': dump_tuple(get_theme().COLOR_NORMAL_TEXT),
                'subject': subject,
                'user': '',
            }
            if nick_from:
                user = tab.get_user_by_name(nick_from)
                if nick_from == tab.own_nick:
                    after = ' (You)'
                else:
                    after = ''
                if user:
                    user_col = dump_tuple(user.color)
                    user_string = '\x19%s}%s\x19%s}%s' % (user_col, nick_from, fmt['info_col'], after)
                else:
                    user_string = '\x19%s}%s%s' % (fmt['info_col'], nick_from, after)
                fmt['user'] = user_string

            if nick_from:
                tab.add_message("%(user)s set the subject to: \x19%(text_col)s}%(subject)s" % fmt,
                        time=None,
                        typ=2)
            else:
                tab.add_message("\x19%(info_col)s}The subject is: \x19%(text_col)s}%(subject)s" % fmt,
                        time=None,
                        typ=2)
        tab.topic = subject
        tab.topic_from = nick_from
        if self.core.get_tab_by_name(room_from, tabs.MucTab) is self.core.current_tab():
            self.core.refresh_window()

    def on_receipt(self, message):
        """
        When a delivery receipt is received (XEP-0184)
        """
        jid = message['from']
        msg_id = message['receipt']
        if not msg_id:
            return

        conversation = self.core.get_tab_by_name(jid.full, tabs.OneToOneTab)
        conversation = conversation or self.core.get_tab_by_name(jid.bare, tabs.OneToOneTab)
        if not conversation:
            log.error("Received ack from non-existing chat tab: %s", jid)
            return

        try:
            conversation.ack_message(msg_id, self.core.xmpp.boundjid)
        except AckError:
            log.debug('Error while receiving an ack', exc_info=True)

    def on_data_form(self, message):
        """
        When a data form is received
        """
        self.core.information('%s' % message)

    def on_attention(self, message):
        """
        Attention probe received.
        """
        jid_from = message['from']
        self.core.information('%s requests your attention!' % jid_from, 'Info')
        for tab in self.core.tabs:
            if tab.name == jid_from:
                tab.state = 'attention'
                self.core.refresh_tab_win()
                return
        for tab in self.core.tabs:
            if tab.name == jid_from.bare:
                tab.state = 'attention'
                self.core.refresh_tab_win()
                return
        self.core.information('%s tab not found.' % jid_from, 'Error')

    def outgoing_stanza(self, stanza):
        """
        We are sending a new stanza, write it in the xml buffer if needed.
        """
        if self.core.xml_tab:
            if PYGMENTS:
                xhtml_text = highlight('%s' % stanza, LEXER, FORMATTER)
                poezio_colored = xhtml.xhtml_to_poezio_colors(xhtml_text, force=True).rstrip('\x19o').strip()
            else:
                poezio_colored = '%s' % stanza
            self.core.add_message_to_text_buffer(self.core.xml_buffer, poezio_colored,
                                                 nickname=get_theme().CHAR_XML_OUT)
            try:
                if self.core.xml_tab.match_stanza(ElementBase(ET.fromstring(stanza))):
                    self.core.add_message_to_text_buffer(self.core.xml_tab.filtered_buffer, poezio_colored,
                                                         nickname=get_theme().CHAR_XML_OUT)
            except:
                log.debug('', exc_info=True)

            if isinstance(self.core.current_tab(), tabs.XMLTab):
                self.core.current_tab().refresh()
                self.core.doupdate()

    def incoming_stanza(self, stanza):
        """
        We are receiving a new stanza, write it in the xml buffer if needed.
        """
        if self.core.xml_tab:
            if PYGMENTS:
                xhtml_text = highlight('%s' % stanza, LEXER, FORMATTER)
                poezio_colored = xhtml.xhtml_to_poezio_colors(xhtml_text, force=True).rstrip('\x19o').strip()
            else:
                poezio_colored = '%s' % stanza
            self.core.add_message_to_text_buffer(self.core.xml_buffer, poezio_colored,
                                                 nickname=get_theme().CHAR_XML_IN)
            try:
                if self.core.xml_tab.match_stanza(stanza):
                    self.core.add_message_to_text_buffer(self.core.xml_tab.filtered_buffer, poezio_colored,
                                                         nickname=get_theme().CHAR_XML_IN)
            except:
                log.debug('', exc_info=True)
            if isinstance(self.core.current_tab(), tabs.XMLTab):
                self.core.current_tab().refresh()
                self.core.doupdate()

    def ssl_invalid_chain(self, tb):
        self.core.information('The certificate sent by the server is invalid.', 'Error')
        self.core.disconnect()

    def validate_ssl(self, pem):
        """
        Check the server certificate using the slixmpp ssl_cert event
        """
        if config.get('ignore_certificate'):
            return
        cert = config.get('certificate')
        # update the cert representation when it uses the old one
        if cert and not ':' in cert:
            cert = ':'.join(i + j for i, j in zip(cert[::2], cert[1::2])).upper()
            config.set_and_save('certificate', cert)

        der = ssl.PEM_cert_to_DER_cert(pem)
        sha1_digest = sha1(der).hexdigest().upper()
        sha1_found_cert = ':'.join(i + j for i, j in zip(sha1_digest[::2], sha1_digest[1::2]))
        sha2_digest = sha512(der).hexdigest().upper()
        sha2_found_cert = ':'.join(i + j for i, j in zip(sha2_digest[::2], sha2_digest[1::2]))
        if cert:
            if sha1_found_cert == cert:
                log.debug('Cert %s OK', sha1_found_cert)
                log.debug('Current hash is SHA-1, moving to SHA-2 (%s)',
                          sha2_found_cert)
                config.set_and_save('certificate', sha2_found_cert)
                return
            elif sha2_found_cert == cert:
                log.debug('Cert %s OK', sha2_found_cert)
                return
            else:
                saved_input = self.core.current_tab().input
                log.debug('\nWARNING: CERTIFICATE CHANGED old: %s, new: %s\n', cert, sha2_found_cert)
                self.core.information('New certificate found (sha-2 hash:'
                                      ' %s)\nPlease validate or abort' % sha2_found_cert,
                                      'Warning')
                def check_input():
                    self.core.current_tab().input = saved_input
                    if input.value:
                        self.core.information('Setting new certificate: old: %s, new: %s' % (cert, sha2_found_cert), 'Info')
                        log.debug('Setting certificate to %s', sha2_found_cert)
                        if not config.silent_set('certificate', sha2_found_cert):
                            self.core.information('Unable to write in the config file', 'Error')
                    else:
                        self.core.information('You refused to validate the certificate. You are now disconnected', 'Info')
                        self.core.disconnect()
                    new_loop.stop()
                    asyncio.set_event_loop(old_loop)
                input = windows.YesNoInput(text="WARNING! Server certificate has changed, accept? (y/n)", callback=check_input)
                self.core.current_tab().input = input
                input.resize(1, self.core.current_tab().width, self.core.current_tab().height-1, 0)
                input.refresh()
                self.core.doupdate()
                old_loop = asyncio.get_event_loop()
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                new_loop.add_reader(sys.stdin, self.core.on_input_readable)
                curses.beep()
                new_loop.run_forever()
        else:
            log.debug('First time. Setting certificate to %s', sha2_found_cert)
            if not config.silent_set('certificate', sha2_found_cert):
                self.core.information('Unable to write in the config file', 'Error')

    ### Ad-hoc commands

    def next_adhoc_step(self, iq, adhoc_session):
        status = iq['command']['status']
        xform = iq.xml.find('{http://jabber.org/protocol/commands}command/{jabber:x:data}x')
        if xform is not None:
            form = self.core.xmpp.plugin['xep_0004'].buildForm(xform)
        else:
            form = None

        if status == 'error':
            return self.core.information("An error occured while executing the command")

        if status == 'executing':
            if not form:
                self.core.information("Adhoc command step does not contain a data-form. Aborting the execution.", "Error")
                return self.core.xmpp.plugin['xep_0050'].cancel_command(adhoc_session)
            on_validate = self._validate_adhoc_step
            on_cancel = self._cancel_adhoc_command
        if status == 'completed':
            on_validate = lambda form, session: self.core.close_tab()
            on_cancel = lambda form, session: self.core.close_tab()

        # If a form is available, use it, and add the Notes from the
        # response to it, if any
        if form:
            for note in iq['command']['notes']:
                form.add_field(type='fixed', label=note[1])
            self.core.open_new_form(form, on_cancel, on_validate,
                                    session=adhoc_session)
        else:                   # otherwise, just display an information
                                # message
            notes = '\n'.join([note[1] for note in iq['command']['notes']])
            self.core.information("Adhoc command %s: %s" % (status, notes), "Info")

    def adhoc_error(self, iq, adhoc_session):
        self.core.xmpp.plugin['xep_0050'].terminate_command(adhoc_session)
        error_message = self.core.get_error_message(iq)
        self.core.information("An error occured while executing the command: %s" % (error_message),
                              'Error')

    def _cancel_adhoc_command(self, form, session):
        self.core.xmpp.plugin['xep_0050'].cancel_command(session)
        self.core.close_tab()

    def _validate_adhoc_step(self, form, session):
        session['payload'] = form
        self.core.xmpp.plugin['xep_0050'].continue_command(session)
        self.core.close_tab()

    def _terminate_adhoc_command(self, form, session):
        self.core.xmpp.plugin['xep_0050'].terminate_command(session)
        self.core.close_tab()

def _composing_tab_state(tab, state):
    """
    Set a tab state to or from the "composing" state
    according to the config and the current tab state
    """
    if isinstance(tab, tabs.MucTab):
        values = ('true', 'muc')
    elif isinstance(tab, tabs.PrivateTab):
        values = ('true', 'direct', 'private')
    elif isinstance(tab, tabs.ConversationTab):
        values = ('true', 'direct', 'conversation')
    else:
        return # should not happen

    show = config.get('show_composing_tabs')
    show = show in values

    if tab.state != 'composing' and state == 'composing':
        if show:
            if tabs.STATE_PRIORITY[tab.state] > tabs.STATE_PRIORITY[state]:
                return
            tab.save_state()
            tab.state = 'composing'
    elif tab.state == 'composing' and state != 'composing':
        tab.restore_state()

