"""
Module exporting all the Windows, which are wrappers around curses wins
used to display information on the screen
"""

from poezio.windows.base_wins import Win
from poezio.windows.data_forms import FormWin
from poezio.windows.bookmark_forms import BookmarksWin
from poezio.windows.info_bar import GlobalInfoBar, VerticalGlobalInfoBar
from poezio.windows.info_wins import InfoWin, XMLInfoWin, PrivateInfoWin, MucListInfoWin, \
        ConversationInfoWin, DynamicConversationInfoWin, MucInfoWin, \
        ConversationStatusMessageWin, BookmarksInfoWin
from poezio.windows.input_placeholders import HelpText, YesNoInput
from poezio.windows.inputs import Input, HistoryInput, MessageInput, CommandInput
from poezio.windows.list import ListWin, ColumnHeaderWin
from poezio.windows.misc import VerticalSeparator
from poezio.windows.muc import UserList, Topic
from poezio.windows.roster_win import RosterWin, ContactInfoWin
from poezio.windows.text_win import TextWin, XMLTextWin

