# ovpn3
OpenVPN 3 CLI for automatic session start with credentials read from os keyring


# Setup

1. First setup `openvpn3` configuration profile: 
    ```bash
    openvpn3 config-import --persistent --name <profile> --config <client.ovpn>
    ```

2. Back `resolv.conf` openvpn3 is known leave the changed version on system restart. 
    ```bash
    sudo cp /etc/resolv.conf /etc/resolv.conf.ovpn3bak
    ```
3. Install `ovpn3` you os py3, so `openvpn3` will be available:
    ```bash
    pip3 install --user ovpn3
    ```

4. Then setup `ovpn3` and store your password and optionally TOTP key in your keyring:
    ```bash
    ovpn3 setup <profile> <username>
    ```

5. Connect with  `ovpn3` credentials will be provided based on data stored in the keyring:
    ```bash
    ovpn3 connect <profile> <username> 
    ```

# Warning

This is still an alpha version with no support. 

## Troubleshooting

Run your commands with DEBUG verbosity:

```bash
ovpn3 -v DEVBUG <cmd>
```

## Known issues

### Resolv conf is not being restored after disconnection

This may not be related to this tool but OpenVPN in general. In some cases
changes done to `/etc/resolv.conf` are not rolled back. OpenVPN does create 
a backup `/etc/resolv.conf.ovpn3bak` but it is sometimes overwritten on 
reconnection.   
