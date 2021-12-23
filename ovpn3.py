#!/usr/bin/python3

import json
import logging
import time
from getpass import getpass
from itertools import count
from pathlib import Path

import backoff as backoff
import click
import click_log
import dbus
import keyring
import openvpn3
import xdg


log = logging.getLogger(__name__)
click_log.basic_config(log)


def get_cfg_path():
    return xdg.xdg_config_home() / 'pyoepnvpn3.json'


def get_cfg():
    path = get_cfg_path()
    if not path.exists():
        return {}
    with path.open('r') as f:
        return json.load(f)


def save_configuration(name, user, path):
    cfg = get_cfg()
    cfg[f'{name}'] = {
        'user': user,
        'path': path,
    }
    log.debug("cfg: %s", cfg)
    path = get_cfg_path()
    log.debug("Saving configuration: %s", path)
    with path.open('w') as f:
        return json.dump(cfg, f, indent=2, sort_keys=True)


def get_configuration(cfg_name):
    cfg = get_cfg().get(cfg_name, {})
    username = cfg.get('user', None)
    path = cfg.get('path', None)
    if not cfg or not (all((username, path))):
        raise ValueError(f'Missing configuration for {cfg_name}: {cfg}')
    print(f'---> cfg {cfg}')
    return username, Path(path)


def get_service_name(cfg_name):
    return f'openvpn-{cfg_name}'


def save_credentials(cfg_name, username, password):
    service_name = get_service_name(cfg_name)
    keyring.set_password(service_name, username, password)


def get_password(cfg_name, username):
    service_name = get_service_name(cfg_name)
    return keyring.get_password(service_name, username)


class VPN:

    def __init__(self, name: str, user: str, path: Path) -> None:
        self.user = user
        self.name = name
        self.path = path
        self.bus: dbus.SystemBus = dbus.SystemBus()
        self.config = self.get_vpn_cfg()

    def get_vpn_cfg(self):
        # Get a connection to the openvpn3-service-configmgr service
        # and import the configuration
        cm = openvpn3.ConfigurationManager(self.bus)
        names = cm.LookupConfigName(self.name)

        if len(names) > 0:
            cfg = cm.Retrieve(names[0])
        else:
            # cmdparser = openvpn3.ConfigParser(), __file__)
            # cmdparser.SanityCheck()
            cfg = cm.Import(self.name, self.path.read_text(), False, False)

        log.debug("Configuration D-Bus path: " + cfg.GetPath())
        return cfg

    def get_session(self):
        # Get a connection to the openvpn3-service-sessionmgr service
        # and start a new tunnel with the just imported config profile
        sm = openvpn3.SessionManager(self.bus)
        sessions = sm.LookupConfigName(self.name)
        if len(sessions) > 4:
            log.debug("sessions: %s", sessions)
            session = sm.Retrieve(sessions[0])
        else:
            session = sm.NewTunnel(self.config)
        log.debug("session: %s", session)
        log.debug("Session D-Bus path: " + session.GetPath())
        return session

    @backoff.on_exception(
        wait_gen=backoff.expo,
        exception=dbus.exceptions.DBusException,
        max_tries=8,
    )
    def get_status(self, session):
        # Wait for the backends to settle
        # The GetStatus() method will throw an exception
        # if the backend is not yet ready
        status = session.GetStatus()
        log.debug("Status: %s", status)
        return status

    def authenticate(self, session):
        slots = session.FetchUserInputSlots()
        log.info(f'Sending user: {self.user}')
        slots[0].ProvideInput(self.user)
        log.info(f'Sending password: ***')
        password = get_password(cfg_name=self.name, username=self.user)
        slots[1].ProvideInput(password)

    def mfa(self, session):
        slot = session.FetchUserInputSlots()[0]
        label = slot.GetLabel()
        slot.ProvideInput(input(f'{label}: '))
        # TODO: use pyotp here

    def connect(self):
        session = self.get_session()
        self.get_status(session)

        try:
            session.Ready()
        except dbus.exceptions.DBusException as e:
            if not str(e).endswith('Missing user credentials'):
                raise e

            self.get_status(session)
            self.authenticate(session=session)

        session.Ready()
        session.Connect()

        for n in count():
            log.debug(f'[{n}] Waiting for MFA prompt')
            status = self.get_status(session)
            slots = session.FetchUserInputSlots()
            if len(slots) > 0:
                self.mfa(session)
                session.Ready()
                session.Connect()
                log.info("Connected...")
                return
            sec = 0.5
            sec = sec + n * 0.5 if sec < 5 else sec
            log.debug("Waiting: %s", sec)
            time.sleep(sec)
            if n > 10:
                raise Exception("MFA prompt was not requested")

    def disconnect(self):
        session = self.get_session()
        self.get_status(session)
        session.Disconnect()


@click.group(name='pyopenvpn3')
@click_log.simple_verbosity_option(logger=log)
@click.pass_context
def main(ctx, config={}):
    """PyOpenVPN3 CLI"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = config


@click.command()
@click.argument('name', required=True)
@click.argument('path', required=True)
@click.argument('user', required=True)
@click.pass_context
def setup(ctx, name, path, user):
    """Save credentials and sesssion configuration"""
    save_configuration(name=name, user=user, path=path)
    save_credentials(cfg_name=name, username=user, password=getpass(f'Password for {user}: '))


@click.command()
@click.argument('name', required=True)
@click.pass_context
def connect(ctx, name):
    """Connect VPN session"""
    user, path = get_configuration(cfg_name=name)
    vpn = VPN(name=name, user=user, path=path)
    try:
        vpn.connect()
    except Exception as ex:
        vpn.disconnect()
        raise ex


@click.command()
@click.argument('name', required=True)
@click.pass_context
def disconnect(ctx, name):
    """Connect VPN session"""
    user, path = get_configuration(cfg_name=name)
    vpn = VPN(name=name, user=user, path=path)
    vpn.disconnect()


main.add_command(setup)
main.add_command(connect)
# main.add_command(disconnect)

if __name__ == "__main__":
    main(obj={})
