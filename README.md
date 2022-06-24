# PAM module for OAuth 2.0 Device Authorization Grant

[![GitHub](https://img.shields.io/github/license/QCute/pam_oauth2_device.svg?color=4664DA&style=flat-square)](https://github.com/QCute/pam_oauth2_device/blob/master/LICENSE)

PAM module for user authentication using
[OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628).

The following instructions have been tested on [RockyLinux](https://rockylinux.org) 8.5.

## Installation

Install build dependencies.

```bash
# debian/ubuntu
sudo apt install libpam0g-dev libcurl4-openssl-dev
# RHEL/CentOS 7.x-
sudo yum install pam-devel libcurl-devel
# RHEL/CentOS/RockyLinux 8.x-
sudo dnf install pam-devel libcurl-devel
```

Clone the repository, build and install the module.

```bash
git clone https://github.com/QCute/pam_oauth2_device.git
cd pam_oauth2_device
git submodule init
git submodule update
make
sudo make install
```

Or install manually
```bash
sudo mkdir -p /lib64/security
sudo cp pam_oauth2_device.so /lib64/security/
sudo mkdir -p /etc/pam_oauth2_device
sudo cp config_template.json /etc/pam_oauth2_device/config.json
```

Create a configuration file `/etc/pam_oauth2_device/config.json`.
See `config_template.json`.

### Configuration options

Edit `/etc/pam_oauth2_device/config.json`.

- `qr` QR code encodes the authentication URL.
  - `show`: show (`true`, default) or hide (`false`) the QR code
  - `error_correction_level`: allowed correction levels are
    - 0 - low
    - 1 - medium
    - 2 - high
- `users` User mapping from claim configured in _username_attribute_
  to the local account name.
- `oauth` configuration for the OIDC identity provider.
  - `require_mfa`: if `true` the module will modify the requests to ask
    user to perform the MFA.

### Example Configuration for sshd

Edit `/etc/pam.d/sshd`, Enable `pam_oauth2_device.so` module  

```/etc/pam.d/sshd
auth sufficient pam_oauth2_device.so /etc/pam_oauth2_device/config.json
```
Edit `/etc/ssh/sshd_config`

Disable password authentication (enabled default).  
```sshd-config
#PasswordAuthentication yes
PasswordAuthentication no
```

Enable challenge response authentication (enabled default).  
```sshd-config
#ChallengeResponseAuthentication yes
```

Enable PAM (enabled default).  
```sshd-config
UsePAM yes
```
