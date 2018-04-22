# -*- coding: utf-8 -*-

"""Group Chat Logger

This bot is a modified version of the echo2 bot found here:
https://github.com/python-telegram-bot/python-telegram-bot/blob/master/examples/echobot2.py

This bot logs all messages sent in a Telegram Group to a database.

"""

import logging
from logging.config import dictConfig
from logging.handlers import RotatingFileHandler

from telegram.ext import Updater, MessageHandler, Filters
import os
import re
from mwt import MWT

handlers = {
            "console": {
                "class": "logging.StreamHandler",
                "level": "DEBUG",
                "formatter": "f"
            },

            "file_handler": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "INFO",
                "formatter": "f",
                "filename": '../bot_log.log',
                "maxBytes": 10485760,
                "backupCount": 2,
                "encoding": "utf8"
            },
}
logging_config = dict(version=1,
    formatters={
        'f': {'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'}
        },
    handlers=handlers,
    root={
        'handlers': ['console', 'file_handler'],
        'level': logging.DEBUG,
        },
)
dictConfig(logging_config)

logger = logging.getLogger(__name__)


class TelegramMonitorBot:

    def __init__(self):
        self.debug = os.environ.get('DEBUG') is not None

        # Users to notify of violoations
        self.notify_user_ids = (
            list(map(int, os.environ['NOTIFY_USER_IDS'].split(',')))
            if "NOTIFY_USER_IDS" in os.environ else [])

        # List of chat ids that bot should monitor
        self.chat_ids = (
            list(map(int, os.environ['CHAT_IDS'].split(',')))
            if "CHAT_IDS" in os.environ else [])

        # Regex for message patterns that cause user ban
        self.message_ban_patterns = os.environ['MESSAGE_BAN_PATTERNS']
        self.message_ban_re = (re.compile(
            self.message_ban_patterns,
            re.IGNORECASE | re.VERBOSE)
            if self.message_ban_patterns else None)

        # Regex for message patterns that cause message to be hidden
        self.message_hide_patterns = os.environ['MESSAGE_HIDE_PATTERNS']
        self.message_hide_re = (re.compile(
            self.message_hide_patterns,
            re.IGNORECASE | re.VERBOSE)
            if self.message_hide_patterns else None)

        # Regex for name patterns that cause user to be banned
        self.name_ban_patterns = os.environ['NAME_BAN_PATTERNS']
        self.name_ban_re = (re.compile(
            self.name_ban_patterns,
            re.IGNORECASE | re.VERBOSE)
            if self.name_ban_patterns else None)


    @MWT(timeout=60*60)
    def get_admin_ids(self, bot, chat_id):
        """ Returns a list of admin IDs for a given chat. Results are cached for 1 hour. """
        return [admin.user.id for admin in bot.get_chat_administrators(chat_id)]


    def ban_user(self, update):
        """ Ban user """
        kick_success = update.message.chat.kick_member(update.message.from_user.id)


    def security_check_username(self, bot, update):
        """ Test username for security violations """

        full_name = (update.message.from_user.first_name + " "
            + update.message.from_user.last_name)
        if self.name_ban_re and self.name_ban_re.search(full_name):
            # Logging
            log_message = "Ban match full name: {}".format(full_name.encode('utf-8'))
            logger.info(log_message)
            for notify_user_id in self.notify_user_ids:
                logger.info(notify_user_id,"gets notified")
                bot.send_message(
                    chat_id=notify_user_id,
                    text=log_message)
            # Ban the user
            self.ban_user(update)
            # Log in database

        if self.name_ban_re and self.name_ban_re.search(update.message.from_user.username or ''):
            # Logging
            log_message = "Ban match username: {}".format(update.message.from_user.username.encode('utf-8'))
            logger.info(log_message)
            for notify_user_id in self.notify_user_ids:
                bot.send_message(
                    chat_id=notify_user_id,
                    text=log_message)
            # Ban the user
            self.ban_user(update)


    def security_check_message(self, bot, update):
        """ Test message for security violations """

        message = update.message.text
        full_name = (update.message.from_user.first_name + " " + update.message.from_user.last_name)
        user_name = update.message.from_user.username

        logger.info('Checking new message: {}'.format(message))
        if self.message_ban_re and self.message_ban_re.search(message):
            # Logging
            log_message = "Ban message from: {} - {}, match: {}".format(user_name, full_name, update.message.text.encode('utf-8'))
            logger.info(log_message)
            for notify_user_id in self.notify_user_ids:
                bot.send_message(
                    chat_id=notify_user_id,
                    text=log_message)
            # Any message that causes a ban gets deleted
            update.message.delete()
            # Ban the user
            self.ban_user(update)

        elif self.message_hide_re and self.message_hide_re.search(message):
            # Logging
            log_message = "Hide message from: {} - {}, match: {}".format(user_name, full_name,
                                                                        update.message.text.encode('utf-8'))

            logger.info(log_message)
            for notify_user_id in self.notify_user_ids:
                bot.send_message(
                    chat_id=notify_user_id,
                    text=log_message)
            # Delete the message
            update.message.delete()
        else:
            logger.info('Message OK: {}'.format(message[:20]))


    def msg_handler(self, bot, update):
        """ Primary Logger. Handles incoming bot messages and saves them to DB """
        try:
            user = update.message.from_user

            # Limit bot to monitoring certain chats
            logger.info('message: {}, chat_id: {}'.format(update.message.text[:20], update.message.chat_id))
            if update.message.chat_id not in self.chat_ids:
                logger.info('ignoring message: {}'.format(update.message.text[:20]))
                return

            if (self.debug or
                update.message.from_user.id not in self.get_admin_ids(bot, update.message.chat_id)):
                # Security checks
                self.security_check_username(bot, update)
                self.security_check_message(bot, update)
            else:
                logger.info("Skipping checks. User is admin: {}".format(user.id))

        except Exception as e:
            logger.exception("Error: {}".format(e))


    def error(self, bot, update, error):
        """ Log Errors caused by Updates. """
        logger.error("Update '{}' caused error '{}'".format(update, error))


    def start(self):
        """ Start the bot. """

        # Create the EventHandler and pass it your bot's token.
        updater = Updater(os.environ["TELEGRAM_BOT_TOKEN"])

        # Get the dispatcher to register handlers
        dp = updater.dispatcher

        # on different commands - answer in Telegram

        # on noncommand i.e message - echo the message on Telegram
        dp.add_handler(MessageHandler(
            Filters.text,
            lambda bot, update : self.msg_handler(bot, update)
        ))

        # dp.add_handler(MessageHandler(Filters.status_update, status))

        # log all errors
        dp.add_error_handler(
            lambda bot, update, error : self.error(bot, update, error)
        )

        # Start the Bot
        updater.start_polling()

        logger.info("Bot started. Montitoring chats: {}".format(self.chat_ids))

        # Run the bot until you press Ctrl-C or the process receives SIGINT,
        # SIGTERM or SIGABRT. This should be used most of the time, since
        # start_polling() is non-blocking and will stop the bot gracefully.
        updater.idle()


if __name__ == '__main__':
    c = TelegramMonitorBot()

    c.start()
