#!/usr/bin/python3
import base64
import logging
import time
from dataclasses import dataclass
from getpass import getpass

import backoff as backoff
import click
import click_log
import dbus
import keyring
import openvpn3
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor.totp import TOTP

log = logging.getLogger(__name__)
click_log.basic_config(log)


@dataclass(frozen=True)
class CredentialsService:
    profile: str
    username: str

    @property
    def service_name(self):
        return f'openvpn-{self.profile}'

    def save_password(self, password):
        keyring.set_password(self.service_name, self.username, password)

    def get_password(self):
        return keyring.get_password(self.service_name, self.username)

    def save_totp_key(self, key):
        keyring.set_password(self.service_name, 'totp', key)

    def get_totp_code(self):
        key = keyring.get_password(self.service_name, 'totp')
        encoded_key = base64.b32decode(key, casefold=True)
        totp = TOTP(encoded_key, 6, SHA1(), 30, enforce_key_length=False)
        return totp.generate(time.time())


class SessionProvider:
    def __init__(self) -> None:
        bus: dbus.SystemBus = dbus.SystemBus()
        self.configuration_manager = openvpn3.ConfigurationManager(bus)
        self.session_manager = openvpn3.SessionManager(bus)

    def __call__(self, profile: str):
        session = self.get_session(profile)
        if session is None:
            session = self.session_manager.NewTunnel(self.get_config(profile))

        log.debug("session: %s", session)
        log.debug("Session D-Bus path: " + session.GetPath())
        return session

    def get_config(self, profile: str):
        configurations = self.configuration_manager.LookupConfigName(profile)

        if len(configurations) < 1:
            log.info(
                "Please setup a persistent session:\n"
                "openvpn3 config-import --persistent --name {profile} --config <client.ovpn>"
            )
            raise Exception(f'Missing configuration for {profile}')

        return self.configuration_manager.Retrieve(configurations[0])

    def get_session(self, profile: str):
        sessions = self.session_manager.LookupConfigName(profile)
        if len(sessions) > 0:
            log.debug("Sessions: %s", sessions)
            return self.session_manager.Retrieve(sessions[0])


class VPN:
    def __init__(self, profile: str) -> None:
        self.session = SessionProvider()(profile=profile)

    @backoff.on_exception(
        wait_gen=backoff.expo,
        exception=dbus.exceptions.DBusException,
        max_tries=8,
    )
    def check_status(self):
        # Wait for the backends to settle
        # The GetStatus() method will throw an exception
        # if the backend is not yet ready
        status = self.session.GetStatus()
        log.debug("Status: %s", status)
        return status

    def authenticate(self, credentials_service: CredentialsService):
        slots = self.session.FetchUserInputSlots()
        log.debug("Input slots: %s", slots)
        for slot in slots:
            log.debug("Slot: %s", slot)
            variable_name = slot.GetVariableName()
            if variable_name == 'username':
                username = credentials_service.username
                log.info(f'Sending user: {username}')
                slot.ProvideInput(username)

            if variable_name == 'password':
                log.info(f'Sending password: ***')
                password = credentials_service.get_password()
                slot.ProvideInput(password)

    @backoff.on_predicate(wait_gen=backoff.expo, max_tries=8)
    def mfa(self, credentials_service: CredentialsService):
        self.check_status()
        slots = self.session.FetchUserInputSlots()
        log.debug("Slots: %s", slots)
        if len(slots) < 1:
            log.debug(f'MFA prompt not present')
            return False

        slot = slots[0]
        log.debug("Slot: %s", slot)
        code = credentials_service.get_totp_code()
        if code is not None:
            log.debug(f'Sending TOTP code {code}')
            slot.ProvideInput(code)
        else:
            label = slot.GetLabel()
            slot.ProvideInput(input(f'{label}: '))

        return True

    @backoff.on_predicate(wait_gen=backoff.expo, max_tries=8)
    def wait_for_connection(self):
        status = self.check_status()
        if status['minor'] == openvpn3.StatusMinor.CONN_AUTH_FAILED:
            self.disconnect()
            return True

        if status['minor'] == openvpn3.StatusMinor.CONN_CONNECTED:
            log.info("Connected...")
            return True

    def connect(self, credentials_service: CredentialsService):
        self.check_status()

        try:
            self.session.Ready()
        except dbus.exceptions.DBusException as e:
            if not str(e).endswith('Missing user credentials'):
                raise e

            self.check_status()
            self.authenticate(credentials_service=credentials_service)

        self.check_status()
        self.session.Ready()
        self.session.Connect()

        self.check_status()
        self.mfa(credentials_service=credentials_service)

        self.session.Ready()
        self.session.Connect()
        self.wait_for_connection()

    def disconnect(self):
        self.check_status()
        self.session.Disconnect()


@click.group(name='pyopenvpn3')
@click_log.simple_verbosity_option(logger=log)
@click.pass_context
def main(ctx, config={}):
    """PyOpenVPN3 CLI"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = config


@click.command()
@click.argument('profile', required=True)
@click.argument('username', required=True)
@click.pass_context
def setup(ctx, username, profile):
    """Save credentials for a give profile"""
    service = CredentialsService(profile, username)
    service.save_password(password=getpass(f'Password for {username}: '))
    if input("Do you want to store TOTP key for automatic MFA authentication? [N/y]") == 'y':
        service.save_totp_key(key=getpass(f'TOTP key for {username}: '))


@click.command()
@click.argument('profile', required=True)
@click.argument('username', required=True)
@click.pass_context
def connect(ctx, username, profile):
    """Connect VPN session"""
    credentials_service = CredentialsService(profile, username)
    vpn = VPN(profile=profile)
    try:
        vpn.connect(credentials_service=credentials_service)
    except Exception as ex:
        vpn.disconnect()
        raise ex


@click.command()
@click.argument('profile', required=True)
@click.pass_context
def disconnect(ctx, profile):
    """Disconnect VPN session"""
    vpn = VPN(profile)
    vpn.disconnect()


main.add_command(setup)
main.add_command(connect)
main.add_command(disconnect)

if __name__ == "__main__":
    main(obj={})
