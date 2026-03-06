import ipaddress
import socket
import sys
import os
import os.path
import argparse
import textwrap
import re
import threading
import urllib.request
from datetime import datetime
from binascii import hexlify
from typing import Optional, List

import struct
import base64
import xml.etree.ElementTree as ET

from uuid import UUID

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES, BASE
from ldap3.protocol.microsoft import security_descriptor_control
import ldap3
from colorama import Fore, Style, init
from Cryptodome.Hash import MD4
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.structure import Structure
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key

# ---------------------------------------------------------------------------
# Tee logger – duplicates all stdout/stderr to a log file in the output dir
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

class _TeeWriter:
    """Write to both the original stream and a log file, stripping ANSI colours from the file copy."""
    def __init__(self, stream, log_fh):
        self._stream = stream
        self._log = log_fh

    def write(self, text):
        self._stream.write(text)
        self._log.write(_ANSI_RE.sub('', text))

    def flush(self):
        self._stream.flush()
        self._log.flush()

    # Forward any attribute the caller might check (encoding, isatty, etc.)
    def __getattr__(self, name):
        return getattr(self._stream, name)


# ---------------------------------------------------------------------------
# DACL / ACE constants
# ---------------------------------------------------------------------------

# Access mask bits relevant to AD privilege escalation
_ACE_GENERIC_ALL        = 0x10000000
_ACE_GENERIC_WRITE      = 0x40000000
_ACE_WRITE_OWNER        = 0x00080000
_ACE_WRITE_DACL         = 0x00040000
_ACE_DS_WRITE_PROP      = 0x00000020
_ACE_DS_CONTROL_ACCESS  = 0x00000100
_ACE_DS_SELF            = 0x00000008

# Object-type GUIDs for extended rights / writable properties
_GUID_FORCE_CHANGE_PW   = '00299570-246d-11d0-a768-00aa006e0529'
_GUID_MEMBER_ATTR       = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
_GUID_SPN_ATTR          = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
_GUID_RBCD_ATTR         = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'  # msDS-AllowedToActOnBehalfOfOtherIdentity

# DCSync replication right GUIDs
_GUID_REPL_GET_CHANGES     = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
_GUID_REPL_GET_CHANGES_ALL = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
_GUID_REPL_GET_CHANGES_FIL = '89e95b76-444d-4c62-991a-0facbeda640c'
_REPL_GUID_NAMES = {
    _GUID_REPL_GET_CHANGES:     'DS-Replication-Get-Changes',
    _GUID_REPL_GET_CHANGES_ALL: 'DS-Replication-Get-Changes-All',
    _GUID_REPL_GET_CHANGES_FIL: 'DS-Replication-Get-Changes-In-Filtered-Set',
}

# ADCS enrollment right GUIDs
_GUID_ENROLL      = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
_GUID_AUTOENROLL  = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

# ---------------------------------------------------------------------------
# ADCS / PKI constants
# ---------------------------------------------------------------------------

# EKU OIDs relevant to ADCS privilege escalation
_CLIENT_AUTH_EKUS = {
    '1.3.6.1.5.5.7.3.2',           # Client Authentication
    '1.3.6.1.5.2.3.4',             # PKINIT Client Authentication
    '1.3.6.1.4.1.311.20.2.2',      # Smart Card Logon
    '2.5.29.37.0',                  # Any Purpose
}
_ANY_PURPOSE_EKU  = '2.5.29.37.0'
_ENROLL_AGENT_EKU = '1.3.6.1.4.1.311.20.2.1'  # Certificate Request Agent

# CA rights
_CA_MANAGE  = 0x00000001   # ManageCA
_CA_OFFICER = 0x00000010   # ManageCertificates (Issue & Manage)

# Certificate template name-flag bits
_CT_ENROLLEE_SUPPLIES_SUBJECT     = 0x00000001
_CT_ENROLLEE_SUPPLIES_SUBJECT_ALT = 0x00010000

# Certificate template enrollment-flag bits
_CT_PEND_ALL_REQUESTS   = 0x00000002
_CT_NO_SECURITY_EXT     = 0x00080000

# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag in CA flags
_CA_FLAG_EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000

# ESC11 — IF_ENFORCEENCRYPTICERTREQUEST not set (flag bit 0x01 absent means no encryption required)
_CA_FLAG_IF_ENFORCEENCRYPTICERTREQUEST = 0x00000001

# Template names that are built-in CA/SubCA types — skip in template-based ESC checks
_CA_TYPE_TEMPLATES = {'CA', 'SubCA', 'CrossCA', 'RootCertificateAuthority'}

# Kerberos SPN prefixes that are dangerous delegation targets on DCs
_DANGEROUS_SVC_PREFIXES = (
    'ldap/', 'ldaps/', 'krbtgt/', 'host/', 'cifs/', 'gc/', 'rpcss/', 'dnshost/',
)

# ACE types (allow only)
_ACE_TYPE_ACCESS_ALLOWED        = 0x00
_ACE_TYPE_ACCESS_ALLOWED_OBJECT = 0x05

# Well-known privileged RIDs (appended to domain SID)
_PRIV_RIDS = {'498', '512', '516', '517', '518', '519', '521'}

# Well-known privileged built-in SIDs
_PRIV_BUILTIN_SIDS = {
    'S-1-5-18',      # SYSTEM
    'S-1-5-9',       # Enterprise Domain Controllers
    'S-1-5-32-544',  # Administrators
    'S-1-5-32-548',  # Account Operators (builtin)
    'S-1-5-32-549',  # Server Operators
    'S-1-5-32-550',  # Print Operators
    'S-1-5-32-551',  # Backup Operators
    'S-1-5-32-569',  # Cryptographic Operators
}

# Trustees that are expected/normal — skip in DACL noise reduction
_SKIP_TRUSTEES = {
    'domain admins', 'enterprise admins', 'administrators',
    'account operators', 'schema admins', 'group policy creator owners',
    'system', 'creator owner', 'nt authority\\system',
    'domain controllers', 'enterprise domain controllers',
}


def print_info(msg):
    print(Fore.YELLOW + Style.BRIGHT + str(msg) + Style.RESET_ALL)

def print_success(msg):
    print(Fore.GREEN + Style.BRIGHT + str(msg) + Style.RESET_ALL)

def print_error(msg):
    print(Fore.RED + Style.BRIGHT + str(msg) + Style.RESET_ALL)


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version', '<H'),
        ('Reserved', '<H'),
        ('Length', '<L'),
        ('CurrentPasswordOffset', '<H'),
        ('PreviousPasswordOffset', '<H'),
        ('QueryPasswordIntervalOffset', '<H'),
        ('UnchangedPasswordIntervalOffset', '<H'),
        ('CurrentPassword', ':'),
        ('PreviousPassword', ':'),
        ('QueryPasswordInterval', ':'),
        ('UnchangedPasswordInterval', ':'),
    )

    def __init__(self, data=None):
        super().__init__(data=data)

    def fromString(self, data):
        super().fromString(data)
        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']
        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]
        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]


class LDAPSearch:
    def __init__(self):
        self.args = None
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.hash: Optional[str] = None
        self.hostname: Optional[str] = None
        self.server: Optional[Server] = None
        self.conn: Optional[Connection] = None
        self.dir_name: Optional[str] = None
        self.name_context: Optional[str] = None
        self.dom_1: Optional[str] = None
        self.dc_val: Optional[int] = None
        self.long_dc: Optional[str] = None
        self.domain: Optional[str] = None
        self.t1: Optional[datetime] = None
        self.t2: Optional[datetime] = None
        self.subnet: Optional[str] = None
        self.no_ssl: bool = False
        self.group_members: bool = False
        self.rbcd: bool = False
        self.dacl: Optional[str] = None
        self.dacl_type: Optional[str] = None
        # Vulnerability scan flags
        self.adminsdholder: bool = False
        self.sid_history: bool = False
        self.shadow_creds: bool = False
        self.foreign_principals: bool = False
        self.dangerous_delegation: bool = False
        self.rbcd_domain: bool = False
        self.indirect_admins: bool = False
        self.dcsync: bool = False
        self.protected_users: bool = False
        self.adcs_esc1: bool = False
        self.adcs_esc2: bool = False
        self.adcs_esc3: bool = False
        self.adcs_esc4: bool = False
        self.adcs_esc5: bool = False
        self.adcs_esc6: bool = False
        self.adcs_esc7: bool = False
        self.adcs_esc8: bool = False
        self.adcs_esc9: bool = False
        self.adcs_esc10: bool = False
        self.adcs_esc11: bool = False
        self.adcs_esc13: bool = False
        self.adcs_esc15: bool = False
        self.adcs_weak_key: bool = False
        self.rc4: bool = False
        self.pre_win2k: bool = False
        self.vuln_scan: bool = False   # runs all of the above
        self.targeted_mode: bool = False
        self.run_ts: str = ""              # set at bind time: "YYYY-MM-DD HH:MM"
        self._log_fh = None                # set by _create_output_dir

    def banner(self):
        print_info("")
        print(r'             _  _     ____    ___    ____  ')
        print( '   ____ ____/ |/ /   / __ \\  /   |  / __ \\')
        print(r'  / __ `/ __  / /   / / / / / /| | / /_/ /')
        print(r' / /_/ / /_/ / /___/ /_/ / / ___ |/ ____/ ')
        print( ' \\__,_/\\__,_/_____/_____/ /_/  |_/_/      ')
        print('           AD LDAP Enum v0.3')
        print("              Beatenyou \n" + Style.RESET_ALL)

    def arg_handler(self):
        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent(
                '''\
Examples:
  Anonymous Bind:          python3 adLDAP.py -a --dc 192.168.1.79
  Authenticated Bind:      python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123!
  NTLM Bind:               python3 adLDAP.py --dc 192.168.1.79 --user testuser --ntlm <hash>
  Force Port 389:          python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --no-ssl
  Group Members:           python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --group-members
  RBCD Enumeration:        python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --rbcd
  DACL (all):              python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --dacl
  DACL (one object):       python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --dacl K2ROOTDC$
  DACL (one user):         python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --dacl jdoe --dacl-type user
  ────── Vulnerability / Security Checks ──────
  Run ALL vuln checks:     python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --vuln-scan
  AdminSDHolder ACL:       python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adminsdholder
  SID History Abuse:       python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --sid-history
  Shadow Credentials:      python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --shadow-creds
  Foreign Principals:      python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --foreign-principals
  Dangerous Delegation:    python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --dangerous-delegation
  RBCD on Domain/DCs:      python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --rbcd-domain
  Indirect Admins:         python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --indirect-admins
  DCSync Rights:           python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --dcsync
  Protected Users:         python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --protected-users
  ADCS ESC1:               python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc1
  ADCS ESC2:               python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc2
  ADCS ESC3:               python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc3
  ADCS ESC4:               python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc4
  ADCS ESC5:               python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc5
  ADCS ESC6:               python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc6
  ADCS ESC7:               python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc7
  ADCS ESC8:               python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc8
  ADCS ESC9:               python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc9
  ADCS ESC10:              python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc10
  ADCS ESC11:              python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc11
  ADCS ESC13:              python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc13
  ADCS ESC15:              python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-esc15
  ADCS Weak Keys:          python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --adcs-weak-key
  RC4 Encryption:          python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --rc4
  Pre-Win2000 Group:       python3 adLDAP.py --dc 192.168.1.79 --user testuser --password Password123! --pre-win2k
''')
        )
        target = parser.add_argument_group('Target')
        target.add_argument('-d', '--dc', required=True, help='Domain controller IP.')
        target.add_argument('-sn', '--subnet', help='Quick portscan for DCs (ex. 192.168.1.0; /24 only).')
        anon = parser.add_argument_group('Anonymous Bind')
        anon.add_argument('-a', '--anon', action='store_true', help='Anonymous bind checks only.')
        auth = parser.add_argument_group('Authenticated Bind')
        auth.add_argument('-u', '--user', help='Username to authenticate with.')
        auth.add_argument('-p', '--password', help='Password to authenticate with.')
        auth.add_argument('-n', '--ntlm', help='NTLM hash to use in place of a password.')
        auth.add_argument('-dn', '--domain', help='Domain name, if unknown.')
        # Force port 389, skipping the LDAPS attempt
        auth.add_argument(
            '--no-ssl',
            action='store_true',
            help='Force plain LDAP on port 389 (skip LDAPS on port 636). '
                 'Useful when the DC does not have LDAPS configured.'
        )
        # Enumerate members of every group found
        auth.add_argument(
            '-gm', '--group-members',
            action='store_true',
            help='Enumerate and display members of every group discovered during the run.'
        )
        # Enumerate Resource Based Constrained Delegation
        auth.add_argument(
            '--rbcd',
            action='store_true',
            help='Enumerate Resource Based Constrained Delegation '
                 '(msDS-AllowedToActOnBehalfOfOtherIdentity) on computers and users.'
        )
        # Enumerate dangerous DACL ACEs — optional value narrows to a single object
        auth.add_argument(
            '--dacl',
            nargs='?',
            const='__all__',    # --dacl with no value  → enumerate everything
            default=None,       # flag absent           → skip DACL entirely
            metavar='OBJECT_NAME',
            help='Enumerate DACL ACEs for dangerous rights. '
                 'Without a value, scans all objects. '
                 'Supply a sAMAccountName (e.g. --dacl K2ROOTDC$) to target one object. '
                 'Combine with --dacl-type to scope the search.'
        )
        # Narrow --dacl to a specific object class
        auth.add_argument(
            '--dacl-type',
            choices=['user', 'computer', 'group'],
            default=None,
            metavar='TYPE',
            help='Restrict --dacl to a specific object type: user, computer, or group. '
                 'When used with a named target (--dacl NAME), this disambiguates '
                 'objects that share a sAMAccountName across classes.'
        )
        # ── Vulnerability / Security Checks ─────────────────────────────
        vuln = parser.add_argument_group(
            'Vulnerability & Security Checks',
            'Targeted AD security checks. Use --vuln-scan to run all at once.'
        )
        vuln.add_argument('--vuln-scan', action='store_true',
            help='Run ALL vulnerability checks in one pass.')
        vuln.add_argument('--adminsdholder', action='store_true',
            help='Inspect AdminSDHolder ACL for unexpected write permissions (SDProp persistence).')
        vuln.add_argument('--sid-history', action='store_true',
            help='Detect accounts carrying privileged SIDs in sIDHistory.')
        vuln.add_argument('--shadow-creds', action='store_true',
            help='Enumerate msDS-KeyCredentialLink entries (Shadow Credentials).')
        vuln.add_argument('--foreign-principals', action='store_true',
            help='Find Foreign Security Principals in privileged groups.')
        vuln.add_argument('--dangerous-delegation', action='store_true',
            help='Find constrained delegation targets on sensitive DC services (ldap/cifs/host/gc).')
        vuln.add_argument('--rbcd-domain', action='store_true',
            help='Check if RBCD is set on the domain object or DC computer objects.')
        vuln.add_argument('--indirect-admins', action='store_true',
            help='Find transitive (nested) members of privileged groups not directly listed.')
        vuln.add_argument('--dcsync', action='store_true',
            help='Find non-privileged principals with DCSync replication rights.')
        vuln.add_argument('--protected-users', action='store_true',
            help='Report Protected Users group membership and flag missing privileged accounts.')
        vuln.add_argument('--adcs-esc1', action='store_true',
            help='Find templates with enrollee-supplied SAN + client auth (ESC1).')
        vuln.add_argument('--adcs-esc2', action='store_true',
            help='Find templates with Any Purpose / no EKU (ESC2).')
        vuln.add_argument('--adcs-esc3', action='store_true',
            help='Find enrollment agent templates without approval (ESC3).')
        vuln.add_argument('--adcs-esc4', action='store_true',
            help='Find non-privileged write ACEs on certificate templates (ESC4).')
        vuln.add_argument('--adcs-esc5', action='store_true',
            help='Find non-privileged write ACEs on PKI container objects (ESC5).')
        vuln.add_argument('--adcs-esc6', action='store_true',
            help='Check if CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (ESC6).')
        vuln.add_argument('--adcs-esc7', action='store_true',
            help='Find non-privileged CA Officer/Manager rights (ESC7).')
        vuln.add_argument('--adcs-esc8', action='store_true',
            help='Check if HTTP web enrollment (certsrv) is accessible (ESC8).')
        vuln.add_argument('--adcs-esc9', action='store_true',
            help='Find templates with CT_FLAG_NO_SECURITY_EXTENSION + client auth (ESC9).')
        vuln.add_argument('--adcs-esc10', action='store_true',
            help='Report client auth templates vulnerable to weak cert mapping (ESC10).')
        vuln.add_argument('--adcs-esc11', action='store_true',
            help='Check if CA accepts non-encrypted RPC requests (ESC11).')
        vuln.add_argument('--adcs-esc13', action='store_true',
            help='Find templates with issuance policy linked to AD group (ESC13).')
        vuln.add_argument('--adcs-esc15', action='store_true',
            help='Find schema v1 templates with enrollee-supplied SAN + client auth (ESC15).')
        vuln.add_argument('--adcs-weak-key', action='store_true',
            help='Find certificate templates with key size below 2048-bit.')
        vuln.add_argument('--rc4', action='store_true',
            help='Find service accounts and DCs permitting RC4 Kerberos encryption.')
        vuln.add_argument('--pre-win2k', action='store_true',
            help='Check Pre-Windows 2000 Compatible Access group for Everyone/Anonymous.')

        self.args = parser.parse_args()
        self.hostname = self.args.dc
        self.username = self.args.user
        self.password = self.args.password
        self.hash = self.args.ntlm
        self.subnet = self.args.subnet
        self.no_ssl = self.args.no_ssl
        self.group_members = self.args.group_members
        self.rbcd = self.args.rbcd
        self.dacl      = self.args.dacl
        self.dacl_type = self.args.dacl_type
        # Vuln flags — each is also enabled by --vuln-scan
        self.vuln_scan            = self.args.vuln_scan
        self.adminsdholder        = self.args.adminsdholder        or self.vuln_scan
        self.sid_history          = self.args.sid_history          or self.vuln_scan
        self.shadow_creds         = self.args.shadow_creds         or self.vuln_scan
        self.foreign_principals   = self.args.foreign_principals   or self.vuln_scan
        self.dangerous_delegation = self.args.dangerous_delegation or self.vuln_scan
        self.rbcd_domain          = self.args.rbcd_domain          or self.vuln_scan
        self.indirect_admins      = self.args.indirect_admins      or self.vuln_scan
        self.dcsync               = self.args.dcsync               or self.vuln_scan
        self.protected_users      = self.args.protected_users      or self.vuln_scan
        self.adcs_esc1            = self.args.adcs_esc1            or self.vuln_scan
        self.adcs_esc2            = self.args.adcs_esc2            or self.vuln_scan
        self.adcs_esc3            = self.args.adcs_esc3            or self.vuln_scan
        self.adcs_esc4            = self.args.adcs_esc4            or self.vuln_scan
        self.adcs_esc5            = self.args.adcs_esc5            or self.vuln_scan
        self.adcs_esc6            = self.args.adcs_esc6            or self.vuln_scan
        self.adcs_esc7            = self.args.adcs_esc7            or self.vuln_scan
        self.adcs_esc8            = self.args.adcs_esc8            or self.vuln_scan
        self.adcs_esc9            = self.args.adcs_esc9            or self.vuln_scan
        self.adcs_esc10           = self.args.adcs_esc10           or self.vuln_scan
        self.adcs_esc11           = self.args.adcs_esc11           or self.vuln_scan
        self.adcs_esc13           = self.args.adcs_esc13           or self.vuln_scan
        self.adcs_esc15           = self.args.adcs_esc15           or self.vuln_scan
        self.adcs_weak_key        = self.args.adcs_weak_key        or self.vuln_scan
        self.rc4                  = self.args.rc4                  or self.vuln_scan
        self.pre_win2k            = self.args.pre_win2k            or self.vuln_scan
        self.targeted_mode = any([
            self.group_members, self.rbcd, self.dacl is not None,
            self.adminsdholder, self.sid_history, self.shadow_creds,
            self.foreign_principals, self.dangerous_delegation, self.rbcd_domain,
            self.indirect_admins, self.dcsync, self.protected_users,
            self.adcs_esc1, self.adcs_esc2, self.adcs_esc3,
            self.adcs_esc4, self.adcs_esc5, self.adcs_esc6, self.adcs_esc7,
            self.adcs_esc8, self.adcs_esc9, self.adcs_esc10, self.adcs_esc11,
            self.adcs_esc13, self.adcs_esc15, self.adcs_weak_key,
            self.rc4, self.pre_win2k,
        ])
        if self.args.domain:
            self.domain = self.args.domain

    def portscan(self):
        if not self.subnet:
            print_error("No subnet provided for portscan.")
            return
        socket.setdefaulttimeout(0.05)
        check_ports = [389, 636, 3269]
        print_info(f'[info] Checking for possible domain controllers in the {self.subnet}/24 subnet.')

        def scan_host(host):
            for port in check_ports:
                try:
                    ip_addr = self.subnet[:self.subnet.rfind('.') + 1] + str(host)
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((ip_addr, port))
                        try:
                            host_resolve = socket.gethostbyaddr(ip_addr)[0]
                            print_success(f"[+] Possible Domain Controller found at {ip_addr} - {host_resolve}.")
                        except Exception:
                            print_success(f"[+] Possible Domain Controller found at {ip_addr}.")
                        return
                except (ConnectionRefusedError, AttributeError, OSError):
                    pass

        threads = []
        for host in range(1, 255):
            t = threading.Thread(target=scan_host, args=(host,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        print_info("\n[info] Scan complete. Use identified IPs for further enumeration.")

    def _get_server(self, use_ssl=True) -> Server:
        """
        Create and return an ldap3 Server object.

        If --no-ssl was supplied the caller should always pass use_ssl=False so
        we go straight to port 389.  When use_ssl=True we attempt LDAPS (636).
        """
        try:
            if use_ssl:
                server_val = f'ldaps://{self.hostname}:636'
                return Server(server_val, port=636, use_ssl=True, get_info=ALL)
            else:
                return Server(self.hostname, port=389, use_ssl=False, get_info=ALL)
        except Exception as e:
            print_error(f"Error creating LDAP server object: {e}")
            raise

    def _connect_server(self) -> Server:
        """
        Return a connected (anonymous) Server object, honouring --no-ssl.

        - If --no-ssl is set  → port 389 only, no SSL fallback.
        - Otherwise           → try LDAPS (636) first, fall back to LDAP (389).
        """
        if self.no_ssl:
            print_info("[info] --no-ssl specified: connecting on port 389 (plain LDAP).")
            server = self._get_server(use_ssl=False)
            self.conn = Connection(server, auto_bind=True)
            return server

        # Default: try LDAPS first, then plain LDAP
        try:
            server = self._get_server(use_ssl=True)
            self.conn = Connection(server, auto_bind=True)
            return server
        except Exception:
            print_info("[info] LDAPS (636) failed, falling back to plain LDAP (389).")
            server = self._get_server(use_ssl=False)
            self.conn = Connection(server, auto_bind=True)
            return server

    def _get_domain_context(self, info_str: str) -> None:
        """
        Parse the domain naming context from *info_str* (the ldap3 server.info
        string). Sets self.name_context, self.long_dc, self.dir_name, self.domain.
        """
        try:
            for line in info_str.splitlines():
                stripped = line.strip()
                if stripped.startswith("DC="):
                    self.name_context = stripped
                    self.long_dc = self.name_context
                    self.dc_val = self.name_context.count('DC=')
                    self.name_context = self.name_context.replace("DC=", "").replace(",", ".")
                    if "ForestDnsZones" in self.name_context or "DomainDnsZones" in self.name_context:
                        continue
                    break
            self.dir_name = self.name_context
            if not self.domain:
                self.domain = self.name_context
        except Exception as e:
            print_error(f"Error extracting domain context: {e}")
            raise

    def _create_output_dir(self):
        """Create the domain output directory and start teeing console output to a log file."""
        try:
            # Append timestamp so the folder is e.g. domain.local_2026-03-04_1430
            ts_suffix = self.t1.strftime("_%Y-%m-%d_%H%M") if self.t1 else ""
            self.dir_name = f"{self.dir_name}{ts_suffix}"
            os.makedirs(self.dir_name, exist_ok=True)
            # Open a master log file and tee all subsequent print() output into it
            log_path = os.path.join(self.dir_name, f'{self.domain}.console.log')
            self._log_fh = open(log_path, 'w', encoding='utf-8')
            sys.stdout = _TeeWriter(sys.__stdout__, self._log_fh)
            sys.stderr = _TeeWriter(sys.__stderr__, self._log_fh)
        except Exception as e:
            print_error(f"Error creating output directory: {e}")

    def anonymous_bind(self):
        try:
            self.t1 = datetime.now()
            self.run_ts = self.t1.strftime("%Y-%m-%d %H:%M")
            self.server = self._connect_server()
            info_str = str(self.server.info)
            self._get_domain_context(info_str)
            self._create_output_dir()
            # Write ldapdump directly into the output folder
            out_path = os.path.join(self.dir_name, f'{self.domain}.ldapdump.txt')
            if os.path.exists(out_path):
                os.remove(out_path)
            with open(out_path, 'w') as _f:
                _f.write(info_str)
            print_success(f"[success] Possible domain name found - {self.name_context}")
            print_info('[info] Attempting to gather additional information about the domain.')
            print_info(f'\n[info] All set for now. Come back with credentials to dump additional domain information. Full raw output saved to {out_path}\n')
            self.t2 = datetime.now()
            elapsed = str(self.t2 - self.t1).split(".")[0]
            print_info(f"LDAP enumeration completed in {elapsed}.")
            self._close_log()
        except (ipaddress.AddressValueError, socket.herror):
            print_error("Invalid IP Address or unable to contact host. Please try again.")
            self._close_log()
        except socket.timeout:
            print_error("Timeout while trying to contact the host. Please try again.")
            self._close_log()
        except Exception as e:
            print_error(f"[error] - {e}")
            self._close_log()

    def authenticated_bind(self):
        self.t1 = datetime.now()
        self.run_ts = self.t1.strftime("%Y-%m-%d %H:%M")
        try:
            self.server = self._connect_server()
            info_str = str(self.server.info)
            self._get_domain_context(info_str)
            self._create_output_dir()
            # Write ldapdump directly into the output folder — nothing touches CWD
            out_path = os.path.join(self.dir_name, f'{self.domain}.ldapdump.txt')
            if os.path.exists(out_path):
                os.remove(out_path)
            with open(out_path, 'w') as _f:
                _f.write(info_str)
            print_success(f"[success] Possible domain name found - {self.name_context}")
            self.dom_1 = self.long_dc

            # Try UPN format first, then DOMAIN\user
            user_upn = f"{self.username}@{self.domain}"
            try:
                self.conn = Connection(self.server, user=user_upn, password=self.password, auto_bind=True)
                self.conn.bind()
            except ldap3.core.exceptions.LDAPBindError as e:
                print_info(f"UPN bind failed: {e}. Trying DOMAIN\\user format...")
                dom_name = self.domain.split(".", 1)[0]
                user_sam = f"{dom_name}\\{self.username}"
                try:
                    self.conn = Connection(self.server, user=user_sam, password=self.password, auto_bind=True)
                    self.conn.bind()
                except ldap3.core.exceptions.LDAPBindError as e2:
                    print_error(f"Both UPN and DOMAIN\\user bind failed: {e2}")
                    return

            print_success(f"[success] Connected to {self.hostname}.")
            self.enumerate_all()
        except (ipaddress.AddressValueError, socket.herror):
            print_error("Invalid IP Address or unable to contact host. Please try again.")
            self._close_log()
        except socket.timeout:
            print_error("Timeout while trying to contact the host. Please try again.")
            self._close_log()
        except Exception as e:
            print_error(f"[error] - {e}")
            self._close_log()

    def ntlm_bind(self):
        self.t1 = datetime.now()
        self.run_ts = self.t1.strftime("%Y-%m-%d %H:%M")
        try:
            self.server = self._connect_server()
            info_str = str(self.server.info)
            self._get_domain_context(info_str)
            self._create_output_dir()
            # Write ldapdump directly into the output folder — nothing touches CWD
            out_path = os.path.join(self.dir_name, f'{self.domain}.ldapdump.txt')
            if os.path.exists(out_path):
                os.remove(out_path)
            with open(out_path, 'w') as _f:
                _f.write(info_str)
            print_success(f"[success] Possible domain name found - {self.name_context}")
            self.dom_1 = self.long_dc

            # Try UPN format first, then DOMAIN\user
            user_upn = f"{self.username}@{self.domain}"
            try:
                self.conn = Connection(self.server, user=user_upn, password=self.hash, auto_bind=True, authentication=NTLM)
                self.conn.bind()
            except ldap3.core.exceptions.LDAPBindError as e:
                print_info(f"NTLM UPN bind failed: {e}. Trying DOMAIN\\user format...")
                dom_name = self.domain.split(".", 1)[0]
                user_sam = f"{dom_name}\\{self.username}"
                try:
                    self.conn = Connection(self.server, user=user_sam, password=self.hash, auto_bind=True, authentication=NTLM)
                    self.conn.bind()
                except ldap3.core.exceptions.LDAPBindError as e2:
                    print_error(f"Both NTLM UPN and DOMAIN\\user bind failed. This is usually caused by an incorrect username format, hash, or server configuration. Full error: {e2}")
                    return

            print_success(f"[success] Connected to {self.hostname}.")
            self.enumerate_all()
        except (ipaddress.AddressValueError, socket.herror):
            print_error("Invalid IP Address or unable to contact host. Please try again.")
            self._close_log()
        except socket.timeout:
            print_error("Timeout while trying to contact the host. Please try again.")
            self._close_log()
        except Exception as e:
            print_error(f"[error] - {e}")
            self._close_log()

    def enumerate_all(self):
        if self.targeted_mode:
            print_info('[info] Targeted mode: running only the requested checks.\n')
        else:
            # Full enumeration — core methods
            self.domain_recon()
            self.gmsa_accounts()
            self.laps()
            self.search_users()
            self.search_pass_expire()
            self.search_stale_accounts()
            self.admin_count_search()
            self.search_groups()
            self.admin_accounts()
            self.kerberoast_accounts()
            self.aspreproast_accounts()
            self.unconstrained_search()
            self.constrainted_search()
            self.computer_search()
            self.ad_search()
            self.trusted_domains()
            self.server_search()
            self.deprecated_os()
            self.mssql_search()
            self.exchange_search()
            self.gpo_search()
            self.find_fields()
        if self.group_members:
            self.enumerate_group_members()
        if self.rbcd:
            self.rbcd_search()
        if self.dacl is not None:
            self.dacl_search()
        # ── Vulnerability / Security Checks ─────────────────────────────
        if self.adminsdholder:
            self.check_adminsdholder()
        if self.sid_history:
            self.check_sid_history()
        if self.shadow_creds:
            self.check_shadow_credentials()
        if self.foreign_principals:
            self.check_foreign_principals()
        if self.dangerous_delegation:
            self.check_dangerous_delegation()
        if self.rbcd_domain:
            self.check_rbcd_on_domain()
        if self.indirect_admins:
            self.check_indirect_admins()
        if self.dcsync:
            self.check_dcsync()
        if self.protected_users:
            self.check_protected_users()
        if self.adcs_esc1:
            self.check_adcs_esc1()
        if self.adcs_esc2:
            self.check_adcs_esc2()
        if self.adcs_esc3:
            self.check_adcs_esc3()
        if self.adcs_esc4:
            self.check_adcs_esc4()
        if self.adcs_esc5:
            self.check_adcs_esc5()
        if self.adcs_esc6:
            self.check_adcs_esc6()
        if self.adcs_esc7:
            self.check_adcs_esc7()
        if self.adcs_esc8:
            self.check_adcs_esc8()
        if self.adcs_esc9:
            self.check_adcs_esc9()
        if self.adcs_esc10:
            self.check_adcs_esc10()
        if self.adcs_esc11:
            self.check_adcs_esc11()
        if self.adcs_esc13:
            self.check_adcs_esc13()
        if self.adcs_esc15:
            self.check_adcs_esc15()
        if self.adcs_weak_key:
            self.check_adcs_weak_key()
        if self.rc4:
            self.check_rc4()
        if self.pre_win2k:
            self.check_pre_win2k()
        self._finish()

    def enumerate_group_members(self):
        """
        For every group in the directory, resolve each member DN to a
        sAMAccountName and print a tidy roster.  Results are also written
        to <domain>.group_members.txt.
        """
        print_info('\n' + '-'*28 + 'Group Member Enumeration' + '-'*28 + '\n')
        print_info('[info] Enumerating members for all groups. This may take a moment...\n')

        # Fetch every group along with its member list
        self.conn.search(
            f'{self.dom_1}',
            '(objectclass=group)',
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'member', 'distinguishedName']
        )
        groups = list(self.conn.entries)

        out_path = os.path.join(self.dir_name, f'{self.domain}.group_members.txt')
        if os.path.exists(out_path):
            os.remove(out_path)

        total_groups   = 0
        total_members  = 0

        with open(out_path, 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            for group in groups:
                group_name = str(group.sAMAccountName)
                raw_members = group['member'].values if group['member'] else []

                header = f"\n[Group] {group_name}  ({len(raw_members)} member(s))"
                print_success(header)
                f.write(header + '\n')
                total_groups += 1

                if not raw_members:
                    empty_msg = "  (no members)"
                    print_info(empty_msg)
                    f.write(empty_msg + '\n')
                    continue

                for member_dn in raw_members:
                    # Resolve DN → sAMAccountName (works for users, groups,
                    # computers, and gMSAs alike)
                    self.conn.search(
                        str(member_dn),
                        '(objectClass=*)',
                        search_scope=SUBTREE,
                        attributes=['sAMAccountName', 'objectClass']
                    )
                    if self.conn.entries:
                        entry       = self.conn.entries[0]
                        sam         = str(entry.sAMAccountName)
                        obj_classes = [c.lower() for c in entry['objectClass'].values]

                        # Tag the object type for readability
                        if 'group' in obj_classes:
                            obj_type = 'Group'
                        elif 'computer' in obj_classes:
                            obj_type = 'Computer'
                        elif 'msds-groupmanagedserviceaccount' in obj_classes:
                            obj_type = 'gMSA'
                        else:
                            obj_type = 'User'

                        line = f"  [{obj_type}] {sam}"
                    else:
                        # DN could not be resolved (deleted object, cross-domain, etc.)
                        line = f"  [?] {member_dn}"

                    print_info(line)
                    f.write(line + '\n')
                    total_members += 1

        summary = (f'\n[info] Group member enumeration complete. '
                   f'{total_groups} group(s), {total_members} member reference(s) found.')
        print_info(summary)

    def domain_recon(self):
        print_info('\n' + '-'*31 + 'Domain Enumeration' + '-'*31)
        self.conn.search(
            f'{self.dom_1}', f'(sAMAccountName={self.username})', attributes=ldap3.ALL_ATTRIBUTES)
        for entry in self.conn.entries:
            username = entry.sAMAccountName
            print_success(f"Current User: {username}")
        try:
            groups = self.conn.entries[0]['memberOf']
            print_info("Group Membership(s):")
            for entry in groups:
                entry1 = str(entry)
                remove_cn = entry1.replace('CN=', '')
                group_name = remove_cn.split(',')
                group = str(group_name[0])
                print_success(group)
        except Exception:
            pass
        self.conn.search(f'{self.dom_1}', '(objectclass=*)',
                         attributes=['ms-DS-MachineAccountQuota'])
        quota_val = self.conn.entries[0]['ms-DS-MachineAccountQuota']
        self.conn.search(f'{self.dom_1}', '(objectClass=domain)',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries[0]
        entries_val = str(entries_val)
        for entries in self.conn.entries:
            if entries.pwdProperties == 1:
                pass_complexity = "Enabled"
            elif entries.pwdProperties == 0:
                pass_complexity = "Disabled"
            _FUNC_LEVELS = {
                '0': 'Windows 2000', '1': 'Windows 2003 Interim',
                '2': 'Windows 2003', '3': 'Windows 2008',
                '4': 'Windows 2008 R2', '5': 'Windows 2012',
                '6': 'Windows 2012 R2', '7': 'Windows 2016',
            }
            try:
                fl_raw = self.conn.server.info.other.get('domainFunctionality', [''])[0]
                func_level = _FUNC_LEVELS.get(str(fl_raw), str(fl_raw))
            except Exception:
                func_level = 'Unknown'
            recon_lines = [
                f"Domain SID          : {entries.objectSid}",
                f"Domain Created      : {entries.CreationTime}",
                f"Functional Level    : {func_level}",
                f"Machine Acct Quota  : {quota_val}",
                "",
                "Password Policy",
                f"  Lockout Threshold : {entries.lockoutThreshold}",
                f"  Lockout Duration  : {entries.lockoutDuration}",
                f"  Max Password Age  : {entries.maxPwdAge}",
                f"  Min Password Len  : {entries.minPwdLength}",
                f"  Password History  : {entries.pwdHistoryLength}",
                f"  Complexity        : {pass_complexity}",
            ]
            # ── LDAP-based user privilege enumeration ─────────────────
            try:
                self.conn.search(
                    f'{self.dom_1}',
                    f'(sAMAccountName={self.username})',
                    attributes=['userAccountControl', 'adminCount',
                                'memberOf', 'objectSid'])
                if self.conn.entries:
                    u = self.conn.entries[0]

                    # Decode UserAccountControl flags
                    uac = int(str(u.userAccountControl)) if u.userAccountControl else 0
                    _UAC_FLAGS = {
                        0x0002:    'ACCOUNTDISABLE',
                        0x0010:    'LOCKOUT',
                        0x0020:    'PASSWD_NOTREQD',
                        0x0080:    'ENCRYPTED_TEXT_PWD_ALLOWED',
                        0x0200:    'NORMAL_ACCOUNT',
                        0x10000:   'DONT_EXPIRE_PASSWORD',
                        0x40000:   'SMARTCARD_REQUIRED',
                        0x80000:   'TRUSTED_FOR_DELEGATION',
                        0x100000:  'NOT_DELEGATED',
                        0x200000:  'USE_DES_KEY_ONLY',
                        0x400000:  'DONT_REQ_PREAUTH',
                        0x800000:  'PASSWORD_EXPIRED',
                        0x1000000: 'TRUSTED_TO_AUTH_FOR_DELEGATION',
                    }
                    active_flags = [name for bit, name in _UAC_FLAGS.items() if uac & bit]
                    recon_lines.append('')
                    recon_lines.append('Current User Account Flags')
                    recon_lines.append(f'  UAC Value         : {uac}')
                    recon_lines.append(f'  Flags             : {", ".join(active_flags) if active_flags else "(none)"}')

                    # adminCount
                    admin_count = str(u.adminCount) if u.adminCount else '0'
                    recon_lines.append(f'  adminCount        : {admin_count}')

                    # Check privileged group membership via LDAP_MATCHING_RULE_IN_CHAIN (transitive)
                    _PRIV_GROUPS = [
                        'Domain Admins', 'Enterprise Admins', 'Schema Admins',
                        'Administrators', 'Account Operators', 'Server Operators',
                        'Backup Operators', 'Print Operators', 'DnsAdmins',
                        'Group Policy Creator Owners', 'Protected Users',
                    ]
                    priv_hits = []
                    for pg in _PRIV_GROUPS:
                        try:
                            # 1.2.840.113556.1.4.1941 = LDAP_MATCHING_RULE_IN_CHAIN (recursive)
                            self.conn.search(
                                f'{self.dom_1}',
                                f'(&(sAMAccountName={self.username})(memberOf:1.2.840.113556.1.4.1941:=CN={pg},CN=Users,{self.long_dc}))',
                                attributes=['sAMAccountName'])
                            if not self.conn.entries:
                                # Also check Builtin container
                                self.conn.search(
                                    f'{self.dom_1}',
                                    f'(&(sAMAccountName={self.username})(memberOf:1.2.840.113556.1.4.1941:=CN={pg},CN=Builtin,{self.long_dc}))',
                                    attributes=['sAMAccountName'])
                            if self.conn.entries:
                                priv_hits.append(pg)
                        except Exception:
                            pass
                    recon_lines.append('')
                    recon_lines.append('Privileged Group Membership (transitive)')
                    if priv_hits:
                        for pg in priv_hits:
                            recon_lines.append(f'  [!] {pg}')
                    else:
                        recon_lines.append('  (none detected)')
            except Exception:
                pass

            for ln in recon_lines:
                print_success(ln)
            # Save to file
            out_path = os.path.join(self.dir_name, f'{self.domain}.domain_recon.txt')
            ts_hdr = f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n"
            if os.path.exists(out_path):
                os.remove(out_path)
            with open(out_path, 'w') as _f:
                _f.write(ts_hdr + '\n'.join(recon_lines) + '\n')
        return self.conn.entries

    def gmsa_accounts(self):
        gmsa_accounts = []
        gmsa_file_lines: list = []
        try:
            print_info('\n' + '-'*25 + 'Group Managed Service Accounts' + '-'*26 + '\n')
            self.conn.search(f'{self.dom_1}', '(&(ObjectClass=msDS-GroupManagedServiceAccount))', attributes=['sAMAccountName', 'msDS-ManagedPassword', 'msDS-GroupMSAMembership'])
            gmsa_val = self.conn.entries
            for accounts in gmsa_val:
                gmsa_accounts.append(accounts.sAMAccountName)
            for entry in self.conn.entries:
                    sam = entry['sAMAccountName'].value
                    for dacl in SR_SECURITY_DESCRIPTOR(data=entry['msDS-GroupMSAMembership'].raw_values[0])['Dacl']['Data']:
                        self.conn.search(f'{self.dom_1}', '(&(objectSID='+dacl['Ace']['Sid'].formatCanonical()+'))', attributes=['sAMAccountName'])
                        if len(self.conn.entries) != 0:
                            print_info('Users or groups who can read password for '+sam+':')
                            print_success(' > ' + self.conn.entries[0]['sAMAccountName'].value)

                    if 'msDS-ManagedPassword' in entry and entry['msDS-ManagedPassword']:
                        data = entry['msDS-ManagedPassword'].raw_values[0]
                        blob = MSDS_MANAGEDPASSWORD_BLOB()
                        blob.fromString(data)
                        currentPassword = blob['CurrentPassword'][:-2]

                        ntlm_hash = MD4.new ()
                        ntlm_hash.update (currentPassword)
                        passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                        print_info(f'-- Hashes for {sam} --')
                        userpass = sam + ':aad3b435b51404eeaad3b435b51404ee:' + passwd
                        print_success(userpass)

                        password = currentPassword.decode('utf-16-le', 'replace').encode('utf-8')
                        salt = '%shost%s.%s' % (self.args.domain.upper(), sam[:-1].lower(), self.args.domain.lower())
                        aes_128_hash = hexlify(string_to_key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, password, salt).contents)
                        aes_256_hash = hexlify(string_to_key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, password, salt).contents)
                        print_success('%s:aes256-cts-hmac-sha1-96:%s' % (sam, aes_256_hash.decode('utf-8')))
                        print_success('%s:aes128-cts-hmac-sha1-96:%s' % (sam, aes_128_hash.decode('utf-8')))
                        gmsa_file_lines.append('%s:aes256-cts-hmac-sha1-96:%s' % (sam, aes_256_hash.decode('utf-8')))
                        gmsa_file_lines.append('%s:aes128-cts-hmac-sha1-96:%s' % (sam, aes_128_hash.decode('utf-8')))
        except Exception:
            pass
        # Save whatever was found to file
        if gmsa_file_lines:
            out_path = os.path.join(self.dir_name, f'{self.domain}.gmsa.txt')
            ts_hdr = f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n"
            if os.path.exists(out_path):
                os.remove(out_path)
            with open(out_path, 'w') as _f:
                _f.write(ts_hdr + '\n'.join(gmsa_file_lines) + '\n')

    def laps(self):
        print_info('\n' + '-'*33 + 'LAPS Passwords' + '-'*33 +
              '\n This relies on the current user having permissions to read LAPS passwords\n')
        try:
            self.conn.search(
                f'{self.dom_1}', '(ms-MCS-AdmPwd=*)', attributes=['ms-Mcs-AdmPwd'])
            entries_val = self.conn.entries
            entries_val = str(entries_val)
            for entry in self.conn.entries:
                print_success(str(entry))
            if os.path.exists(os.path.join(self.dir_name, f'{self.domain}.laps.txt')):
                os.remove(os.path.join(self.dir_name, f'{self.domain}.laps.txt'))
            with open(os.path.join(self.dir_name, f'{self.domain}.laps.txt'), 'w') as f:
                f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
                f.write(entries_val)

        except Exception:
            pass

    def search_users(self):
        self.conn.search(
            f'{self.dom_1}', '(&(objectclass=person)(objectCategory=Person))', search_scope=SUBTREE, attributes=ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print_info('\n' + '-'*38 + 'Users' + '-'*37 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(os.path.join(self.dir_name, f'{self.domain}.users.txt')):
            os.remove(os.path.join(self.dir_name, f'{self.domain}.users.txt'))
        with open(os.path.join(self.dir_name, f'{self.domain}.users.txt'), 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(entries_val)

        for users in self.conn.entries:
            try:
                upn = ''
                try:
                    upn = str(users.userPrincipalName) if users.userPrincipalName else ''
                except Exception:
                    pass
                if upn and upn != '[]':
                    print_success(f"{users.sAMAccountName}  ({upn})")
                else:
                    print_success(users.sAMAccountName)
                try:
                    uac = int(str(users.userAccountControl))
                    if uac & 0x40000:
                        print_info("  [!] Smart card required for interactive logon")
                    if uac & 0x0080:
                        print_error("  [!] Password stored using reversible encryption")
                except Exception:
                    pass
            except Exception:
                pass

    def search_pass_expire(self):
        self.conn.search(
            f'{self.dom_1}', '(&(objectclass=user)(objectCategory=Person)(userAccountControl:1.2.840.113556.1.4.803:=65536))', attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print_info('\n' + '-'*24 + 'Users With Non-Expiring Passwords' + '-'*23 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(os.path.join(self.dir_name, f'{self.domain}.pass_never_expires.txt')):
            os.remove(os.path.join(self.dir_name, f'{self.domain}.pass_never_expires.txt'))
        with open(os.path.join(self.dir_name, f'{self.domain}.pass_never_expires.txt'), 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(entries_val)

        try:
            for users in self.conn.entries:
                upn = ''
                try:
                    upn = str(users.userPrincipalName) if users.userPrincipalName else ''
                except Exception:
                    pass
                if upn and upn != '[]':
                    print_success(f"{users.sAMAccountName}  ({upn})")
                else:
                    print_success(users.sAMAccountName)
        except Exception:
            pass

    def search_stale_accounts(self):
        # ── Disabled Accounts ──
        print_info('\n' + '-'*30 + 'Disabled User Accounts' + '-'*28 + '\n')
        self.conn.search(
            f'{self.dom_1}',
            '(&(objectClass=user)(objectCategory=Person)(userAccountControl:1.2.840.113556.1.4.803:=2))',
            attributes=['sAMAccountName', 'userPrincipalName'])
        disabled = []
        for e in self.conn.entries:
            sam = str(e.sAMAccountName)
            upn = ''
            try:
                upn = str(e.userPrincipalName) if e.userPrincipalName else ''
            except Exception:
                pass
            disabled.append((sam, upn if upn and upn != '[]' else ''))
        if disabled:
            for sam, upn in disabled:
                if upn:
                    print_success(f"{sam}  ({upn})")
                else:
                    print_success(sam)
        else:
            print_info('  (none found)')

        # ── Locked-Out Accounts ──
        print_info('\n' + '-'*30 + 'Locked-Out User Accounts' + '-'*26 + '\n')
        self.conn.search(
            f'{self.dom_1}',
            '(&(objectClass=user)(objectCategory=Person)(lockoutTime>=1))',
            attributes=['sAMAccountName', 'lockoutTime', 'userPrincipalName'])
        locked = []
        for e in self.conn.entries:
            lt = str(e.lockoutTime)
            # lockoutTime of 0 means not locked
            if lt and lt != '0' and lt != '1601-01-01 00:00:00+00:00':
                sam = str(e.sAMAccountName)
                upn = ''
                try:
                    upn = str(e.userPrincipalName) if e.userPrincipalName else ''
                except Exception:
                    pass
                locked.append((sam, upn if upn and upn != '[]' else ''))
        if locked:
            for sam, upn in locked:
                if upn:
                    print_success(f"{sam}  ({upn})")
                else:
                    print_success(sam)
        else:
            print_info('  (none found)')

        # ── Never-Logged-On Accounts ──
        print_info('\n' + '-'*27 + 'Users That Have Never Logged On' + '-'*22 + '\n')
        self.conn.search(
            f'{self.dom_1}',
            '(&(objectClass=user)(objectCategory=Person)(!(lastLogonTimestamp=*)))',
            attributes=['sAMAccountName', 'userPrincipalName'])
        never_logon = []
        for e in self.conn.entries:
            sam = str(e.sAMAccountName)
            upn = ''
            try:
                upn = str(e.userPrincipalName) if e.userPrincipalName else ''
            except Exception:
                pass
            never_logon.append((sam, upn if upn and upn != '[]' else ''))
        if never_logon:
            for sam, upn in never_logon:
                if upn:
                    print_success(f"{sam}  ({upn})")
                else:
                    print_success(sam)
        else:
            print_info('  (none found)')

        # Save all to file
        out_path = os.path.join(self.dir_name, f'{self.domain}.stale_accounts.txt')
        if os.path.exists(out_path):
            os.remove(out_path)
        with open(out_path, 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(f"Disabled Accounts ({len(disabled)})\n")
            f.write('\n'.join(f'  {sam}  ({upn})' if upn else f'  {sam}' for sam, upn in disabled) + '\n' if disabled else '  (none found)\n')
            f.write(f"\nLocked-Out Accounts ({len(locked)})\n")
            f.write('\n'.join(f'  {sam}  ({upn})' if upn else f'  {sam}' for sam, upn in locked) + '\n' if locked else '  (none found)\n')
            f.write(f"\nNever-Logged-On Accounts ({len(never_logon)})\n")
            f.write('\n'.join(f'  {sam}  ({upn})' if upn else f'  {sam}' for sam, upn in never_logon) + '\n' if never_logon else '  (none found)\n')

    def search_groups(self):
        self.conn.search(f'{self.dom_1}', '(objectclass=group)',
                         attributes=['sAMAccountName', 'member'])
        groups = list(self.conn.entries)
        print_info('\n' + '-'*37 + 'Groups' + '-'*37 + '\n')
        out_lines = []
        for group in groups:
            group_name = str(group.sAMAccountName)
            raw_members = group['member'].values if group['member'] else []
            member_count = len(raw_members)
            header = f"[Group] {group_name}  ({member_count} member(s))"
            print_success(header)
            out_lines.append(header)
            if raw_members:
                for member_dn in raw_members:
                    # Extract the CN from the DN for a clean display
                    cn = str(member_dn)
                    if cn.upper().startswith('CN='):
                        cn = cn[3:].split(',')[0]
                    line = f"  - {cn}"
                    print_info(line)
                    out_lines.append(line)
            else:
                line = "  (no members)"
                print_info(line)
                out_lines.append(line)
        out_path = os.path.join(self.dir_name, f'{self.domain}.groups.txt')
        if os.path.exists(out_path):
            os.remove(out_path)
        with open(out_path, 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write('\n'.join(out_lines) + '\n')


    def admin_accounts(self):
        try:
            admin_users = []
            self.conn.search(f'{self.dom_1}', '(&(objectclass=group)(CN=*admin*))',
                            attributes=['member'])
            admin_groups = list(self.conn.entries)
            self.conn.search(f'{self.dom_1}', '(&(objectclass=group)(CN=*operator*))',
                            attributes=['member'])
            operator_groups = list(self.conn.entries)
            print_info('\n' + '-'*30 + 'Admin Level Users' + '-'*30 + '\n')

            # Collect all member DNs from both searches
            all_member_dns = []
            for grp in admin_groups + operator_groups:
                members = grp['member'].values if grp['member'] else []
                all_member_dns.extend(str(m) for m in members)

            # Resolve and print unique members
            admin_val = 0
            for member_dn in all_member_dns:
                if member_dn not in admin_users:
                    self.conn.search(member_dn, '(objectClass=user)', attributes=['sAMAccountName', 'userPrincipalName'])
                    for entry in self.conn.entries:
                        upn = ''
                        try:
                            upn = str(entry.userPrincipalName) if entry.userPrincipalName else ''
                        except Exception:
                            pass
                        if upn and upn != '[]':
                            print_success(f"{entry.sAMAccountName}  ({upn})")
                        else:
                            print_success(entry.sAMAccountName)
                    admin_users.append(member_dn)
                    admin_val += 1
                if admin_val >= 25:
                    print_info(f'\n[info] Truncating results at 25. Check {self.domain}.adminusers.txt for full details.')
                    break

            # Save raw data to file
            out_path = os.path.join(self.dir_name, f'{self.domain}.adminusers.txt')
            with open(out_path, 'w') as f:
                f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
                f.write(str(admin_groups))
                f.write(str(operator_groups))
        except Exception as e:
            print(e)

    def kerberoast_accounts(self):
        self.conn.search(f'{self.dom_1}', '(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))',
                         attributes=[ldap3.ALL_ATTRIBUTES])
        entries_val = self.conn.entries
        print_info('\n' + '-'*30 + 'Kerberoastable Users' + '-'*30 + '\n')
        entries_val = str(entries_val)
        for kerb_users in self.conn.entries:
            upn = ''
            try:
                upn = str(kerb_users.userPrincipalName) if kerb_users.userPrincipalName else ''
            except Exception:
                pass
            if upn and upn != '[]':
                print_success(f"{kerb_users.sAMAccountName}  ({upn})")
            else:
                print_success(kerb_users.sAMAccountName)
            try:
                spns = kerb_users.servicePrincipalName.values
                if spns:
                    for spn in spns:
                        print(f"  {spn}")
            except Exception:
                pass
        if os.path.exists(os.path.join(self.dir_name, f'{self.domain}.kerberoast.txt')):
            os.remove(os.path.join(self.dir_name, f'{self.domain}.kerberoast.txt'))
        with open(os.path.join(self.dir_name, f'{self.domain}.kerberoast.txt'), 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(entries_val)


    def aspreproast_accounts(self):
        self.conn.search(f'{self.dom_1}', '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))', attributes=[
            'sAMAccountName', 'userPrincipalName', 'servicePrincipalName'])
        entries_val = self.conn.entries
        print_info('\n' + '-'*30 + 'ASREPRoastable Users' + '-'*30 + '\n')
        entries_val = str(entries_val)
        for asrep_users in self.conn.entries:
            upn = ''
            try:
                upn = str(asrep_users.userPrincipalName) if asrep_users.userPrincipalName else ''
            except Exception:
                pass
            if upn and upn != '[]':
                print_success(f"{asrep_users.sAMAccountName}  ({upn})")
            else:
                print_success(asrep_users.sAMAccountName)
            try:
                spns = asrep_users.servicePrincipalName.values
                if spns:
                    for spn in spns:
                        print(f"  {spn}")
            except Exception:
                pass
        if os.path.exists(os.path.join(self.dir_name, f'{self.domain}.asreproast.txt')):
            os.remove(os.path.join(self.dir_name, f'{self.domain}.asreproast.txt'))
        with open(os.path.join(self.dir_name, f'{self.domain}.asreproast.txt'), 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(entries_val)


    def unconstrained_search(self):
        self.conn.search(f'{self.dom_1}', "(&(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries = list(self.conn.entries)
        print_info('\n' + '-'*28 + 'Unconstrained Delegations' + '-'*27 + '\n')

        # Build row data
        rows = []
        for entry in entries:
            sam = str(entry.sAMAccountName)
            obj_classes = [str(c).lower() for c in (entry.objectClass.values if entry.objectClass else [])]
            if 'computer' in obj_classes:
                acct_type = 'Computer'
            elif 'msds-managedserviceaccount' in obj_classes or 'msds-groupmanagedserviceaccount' in obj_classes:
                acct_type = 'gMSA'
            else:
                acct_type = 'User'
            delegation = 'Any Service (Unconstrained)'
            try:
                spns = [str(s) for s in entry.servicePrincipalName.values] if entry.servicePrincipalName else []
            except Exception:
                spns = []
            rows.append((sam, acct_type, delegation, spns))

        if rows:
            # Calculate column widths
            w_name = max(len('Name'), max(len(r[0]) for r in rows)) + 2
            w_type = max(len('Type'), max(len(r[1]) for r in rows)) + 2
            w_deleg = max(len('Delegation_Rights'), max(len(r[2]) for r in rows)) + 2
            header = f"{'Name':<{w_name}}{'Type':<{w_type}}{'Delegation_Rights':<{w_deleg}}SPNs"
            sep = f"{'-'*w_name}{'-'*w_type}{'-'*w_deleg}{'-'*30}"
            print_info(header)
            print_info(sep)
            for i, (sam, acct_type, delegation, spns) in enumerate(rows):
                first_spn = spns[0] if spns else ''
                print_success(f"{sam:<{w_name}}{acct_type:<{w_type}}{delegation:<{w_deleg}}{first_spn}")
                for spn in spns[1:]:
                    print(f"{'':<{w_name}}{'':<{w_type}}{'':<{w_deleg}}{spn}")
                if i >= 24:
                    print_info(f'\n[info] Truncating results at 25. Check {self.domain}.unconstrained.txt for full details.')
                    break
        else:
            print_info('  (none found)')

        out_path = os.path.join(self.dir_name, f'{self.domain}.unconstrained.txt')
        with open(out_path, 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            if rows:
                for sam, acct_type, delegation, spns in rows:
                    spn_str = ', '.join(spns) if spns else '(none)'
                    f.write(f"{sam}  |  Type: {acct_type}  |  DelegationRightsTo: {delegation}  |  SPNs: {spn_str}\n")
            else:
                f.write('(none found)\n')


    def constrainted_search(self):
        self.conn.search(f'{self.dom_1}', "(msDS-AllowedToDelegateTo=*)",
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries = list(self.conn.entries)
        print_info('\n' + '-'*29 + 'Constrained Delegations' + '-'*28 + '\n')

        # Build row data — one row per delegation target
        rows = []
        for entry in entries:
            sam = str(entry.sAMAccountName)
            obj_classes = [str(c).lower() for c in (entry.objectClass.values if entry.objectClass else [])]
            if 'computer' in obj_classes:
                acct_type = 'Computer'
            elif 'msds-managedserviceaccount' in obj_classes or 'msds-groupmanagedserviceaccount' in obj_classes:
                acct_type = 'gMSA'
            else:
                acct_type = 'User'
            targets = [str(t) for t in (entry['msDS-AllowedToDelegateTo'].values if entry['msDS-AllowedToDelegateTo'] else [])]
            try:
                spns = [str(s) for s in entry.servicePrincipalName.values] if entry.servicePrincipalName else []
            except Exception:
                spns = []
            rows.append((sam, acct_type, targets, spns))

        if rows:
            # Calculate column widths
            all_targets = [t for r in rows for t in r[2]] or ['']
            w_name = max(len('Name'), max(len(r[0]) for r in rows)) + 2
            w_type = max(len('Type'), max(len(r[1]) for r in rows)) + 2
            w_deleg = max(len('Delegation_Rights'), max(len(t) for t in all_targets)) + 2
            header = f"{'Name':<{w_name}}{'Type':<{w_type}}{'Delegation_Rights':<{w_deleg}}SPNs"
            sep = f"{'-'*w_name}{'-'*w_type}{'-'*w_deleg}{'-'*30}"
            print_info(header)
            print_info(sep)
            for i, (sam, acct_type, targets, spns) in enumerate(rows):
                # First line: name, type, first target, first SPN
                first_tgt = targets[0] if targets else ''
                first_spn = spns[0] if spns else ''
                print_success(f"{sam:<{w_name}}{acct_type:<{w_type}}{first_tgt:<{w_deleg}}{first_spn}")
                # Remaining targets and SPNs on subsequent lines
                max_extra = max(len(targets) - 1, len(spns) - 1)
                for j in range(1, max_extra + 1):
                    extra_tgt = targets[j] if j < len(targets) else ''
                    extra_spn = spns[j] if j < len(spns) else ''
                    print(f"{'':<{w_name}}{'':<{w_type}}{extra_tgt:<{w_deleg}}{extra_spn}")
                if i >= 24:
                    print_info(f'\n[info] Truncating results at 25. Check {self.domain}.constrained.txt for full details.')
                    break
        else:
            print_info('  (none found)')

        out_path = os.path.join(self.dir_name, f'{self.domain}.constrained.txt')
        with open(out_path, 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            if rows:
                for sam, acct_type, targets, spns in rows:
                    tgt_str = ', '.join(targets) if targets else '(none)'
                    spn_str = ', '.join(spns) if spns else '(none)'
                    f.write(f"{sam}  |  Type: {acct_type}  |  DelegationRightsTo: {tgt_str}  |  SPNs: {spn_str}\n")
            else:
                f.write('(none found)\n')


    def computer_search(self):
        self.conn.search(f'{self.dom_1}', '(&(objectClass=computer)(!(objectclass=msDS-ManagedServiceAccount)))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries = list(self.conn.entries)
        print_info('\n' + '-'*36 + 'Computers' + '-'*35 + '\n')
        for comp_account in entries:
            print_success(f"{comp_account.name}")
            try:
                spns = comp_account.servicePrincipalName.values
                if spns:
                    for spn in spns:
                        print(f"  {spn}")
            except Exception:
                pass
        out_path = os.path.join(self.dir_name, f'{self.domain}.computers.txt')
        with open(out_path, 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(str(entries))

        if sys.platform.startswith('win32'):
            print_info("\n[info] Let's try to resolve hostnames to IP addresses. This may take some time depending on the number of computers...\n")
            for entry in entries:
                comp_name = str(entry.sAMAccountName).replace('$', '')
                try:
                    comp_ip = socket.gethostbyname(comp_name)
                    if comp_ip:
                        print_success(f'{comp_name} - {comp_ip}')
                except socket.gaierror:
                    pass

    def server_search(self):
        self.conn.search(f'{self.dom_1}', '(&(objectClass=computer)(!(objectclass=msDS-ManagedServiceAccount)))',
                         attributes=['name', 'operatingsystem', 'servicePrincipalName'])
        entries_val = self.conn.entries
        print_info('\n' + '-'*37 + 'Servers' + '-'*36 + '\n')
        entries_val = str(entries_val)
        for comp_account in self.conn.entries:
            comp_account1 = str(comp_account).lower()
            if "server" in comp_account1:
                print_success(f"{comp_account.name} - {comp_account.operatingsystem}")
                try:
                    spns = comp_account.servicePrincipalName.values
                    if spns:
                        for spn in spns:
                            print(f"  {spn}")
                except Exception:
                    pass
        if os.path.exists(os.path.join(self.dir_name, f'{self.domain}.servers.txt')):
            os.remove(os.path.join(self.dir_name, f'{self.domain}.servers.txt'))
        with open(os.path.join(self.dir_name, f'{self.domain}.servers.txt'), 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(entries_val)


    def deprecated_os(self):
        DEPRECATED = ("windows 7", "windows 2003", "2003 r2", "windows 2008",
                      "windows 8", "windows xp", "windows vista")
        self.conn.search(f'{self.dom_1}', '(operatingSystem=*)',
                         attributes=['name', 'operatingSystem', 'dNSHostName', 'servicePrincipalName'])
        print_info('\n' + '-'*26 + 'Deprecated Operating Systems' + '-'*26 + '\n')
        hits: list = []
        for entry in self.conn.entries:
            os_str = str(entry.operatingSystem or '').lower()
            if any(tag in os_str for tag in DEPRECATED):
                line = f"{entry.name} - {entry.operatingSystem}"
                print_success(line)
                try:
                    spns = entry.servicePrincipalName.values
                    if spns:
                        for spn in spns:
                            print(f"  {spn}")
                except Exception:
                    pass
                hits.append(line)
        out_path = os.path.join(self.dir_name, f'{self.domain}.deprecated_os.txt')
        ts_hdr = f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n"
        if os.path.exists(out_path):
            os.remove(out_path)
        with open(out_path, 'w') as _f:
            _f.write(ts_hdr)
            _f.write('\n'.join(hits) + '\n' if hits else '(none found)\n')
        if not hits:
            print_info('  (none found)')
    def ad_search(self):
        self.conn.search(f'{self.dom_1}', '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print_info('\n' + '-'*31 + 'Domain Controllers' + '-'*31 + '\n')
        entries_val = str(entries_val)
        for dc_accounts in self.conn.entries:
            try:
                print_success(dc_accounts.dNSHostName)
            except ldap3.core.exceptions.LDAPCursorAttributeError:
                print_success(dc_accounts.name)
            try:
                spns = dc_accounts.servicePrincipalName.values
                if spns:
                    for spn in spns:
                        print(f"  {spn}")
            except Exception:
                pass
        if os.path.exists(os.path.join(self.dir_name, f'{self.domain}.domaincontrollers.txt')):
            os.remove(os.path.join(self.dir_name, f'{self.domain}.domaincontrollers.txt'))
        with open(os.path.join(self.dir_name, f'{self.domain}.domaincontrollers.txt'), 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(entries_val)


    def trusted_domains(self):
        self.conn.search(f'{self.dom_1}', '(objectclass=trusteddomain)',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print_info('\n' + '-'*33 + 'Trusted Domains' + '-'*32 + '\n')
        entries_val = str(entries_val)
        for trust_vals in self.conn.entries:
            if trust_vals.trustDirection == 0:
                trust_id = "Disabled"
            elif trust_vals.trustDirection == 1:
                trust_id = "<- Inbound"
            elif trust_vals.trustDirection == 2:
                trust_id = "-> Outbound"
            elif trust_vals.trustDirection == 3:
                trust_id = "<-> Bi-Directional"
            else:
                trust_id = f"Unknown ({trust_vals.trustDirection})"
            print_success(f"{trust_id} trust with {trust_vals.trustPartner}")
        if os.path.exists(os.path.join(self.dir_name, f'{self.domain}.domaintrusts.txt')):
            os.remove(os.path.join(self.dir_name, f'{self.domain}.domaintrusts.txt'))
        with open(os.path.join(self.dir_name, f'{self.domain}.domaintrusts.txt'), 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(entries_val)


    def mssql_search(self):
        self.conn.search(f'{self.dom_1}', '(&(sAMAccountType=805306368)(servicePrincipalName=MSSQL*))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries = list(self.conn.entries)
        print_info('\n' + '-'*34 + 'MSSQL Servers' + '-'*33 + '\n')
        for i, entry in enumerate(entries):
            try:
                hostname = str(entry.dNSHostName).replace('$', '')
                print_success(hostname)
                try:
                    spns = entry.servicePrincipalName.values
                    if spns:
                        for spn in spns:
                            print(f"  {spn}")
                except Exception:
                    pass
            except Exception:
                pass
            if i >= 24:
                print_info(f'\n[info] Truncating results at 25. Check {self.domain}.mssqlservers.txt for full details.')
                break
        out_path = os.path.join(self.dir_name, f'{self.domain}.mssqlservers.txt')
        with open(out_path, 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(str(entries))


    def exchange_search(self):
        self.conn.search(f'{self.dom_1}', '(&(objectCategory=Computer)(servicePrincipalName=exchangeMDB*))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries = list(self.conn.entries)
        print_info('\n' + '-'*32 + 'Exchange Servers' + '-'*32 + '\n')
        for i, entry in enumerate(entries):
            name = str(entry.sAMAccountName).replace('$', '')
            print_success(name)
            try:
                spns = entry.servicePrincipalName.values
                if spns:
                    for spn in spns:
                        print(f"  {spn}")
            except Exception:
                pass
            if i >= 24:
                print_info(f'\n[info] Truncating results at 25. Check {self.domain}.exchangeservers.txt for full details.')
                break
        out_path = os.path.join(self.dir_name, f'{self.domain}.exchangeservers.txt')
        with open(out_path, 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(str(entries))


    def gpo_search(self):
        self.conn.search(f'{self.dom_1}', '(objectclass=groupPolicyContainer)',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print_info('\n' + '-'*30 + 'Group Policy Objects' + '-'*30 + '\n')
        entries_val = str(entries_val)
        for gpo_val in self.conn.entries:
            print_success(f"GPO name: {gpo_val.displayName}\nGPO File Path: {gpo_val.gPCFileSysPath}\n")
        if os.path.exists(os.path.join(self.dir_name, f'{self.domain}.GPO.txt')):
            os.remove(os.path.join(self.dir_name, f'{self.domain}.GPO.txt'))
        with open(os.path.join(self.dir_name, f'{self.domain}.GPO.txt'), 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(entries_val)


    def admin_count_search(self):
        self.conn.search(f'{self.dom_1}', '(&(!(memberof=Builtin))(adminCount=1)(objectclass=person)(objectCategory=Person))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print_info('\n' + '-'*30 + 'Protected Admin Users' + '-'*29 +
              '\nThese are user accounts with adminCount=1 set\n')
        entries_val = str(entries_val)
        for admin_count_val in self.conn.entries:
            upn = ''
            try:
                upn = str(admin_count_val.userPrincipalName) if admin_count_val.userPrincipalName else ''
            except Exception:
                pass
            if upn and upn != '[]':
                print_success(f"{admin_count_val.name}  ({upn})")
            else:
                print_success(admin_count_val.name)
        if os.path.exists(os.path.join(self.dir_name, f'{self.domain}.admincount.txt')):
            os.remove(os.path.join(self.dir_name, f'{self.domain}.admincount.txt'))
        with open(os.path.join(self.dir_name, f'{self.domain}.admincount.txt'), 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write(entries_val)

    def find_fields(self):
        print_info('\n[info] Checking user descriptions for interesting information.')
        self.conn.search(f"{self.dom_1}", '(&(objectClass=person)(objectCategory=Person))', attributes=[
                         'sAMAccountname', 'description'])
        interesting: list = []
        for entry in self.conn.entries:
            val1 = str(entry.description)
            val2 = str(entry.sAMAccountname)
            val3 = val1.lower()
            if "pass" in val3 or "pwd" in val3 or "cred" in val3:
                line = f'User: {val2} - Description: {val1}'
                print_success(line)
                interesting.append(line)
        out_path = os.path.join(self.dir_name, f'{self.domain}.interesting_fields.txt')
        ts_hdr = f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n"
        if os.path.exists(out_path):
            os.remove(out_path)
        with open(out_path, 'w') as _f:
            _f.write(ts_hdr)
            if interesting:
                _f.write('\n'.join(interesting) + '\n')
            else:
                _f.write('(no credential-related descriptions found)\n')

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _guid_bytes_to_str(self, raw: bytes) -> str:
        """Convert a 16-byte little-endian Windows GUID to its string form."""
        try:
            return str(UUID(bytes_le=bytes(raw)))
        except Exception:
            return ''

    def _resolve_sid(self, sid: str) -> str:
        """Resolve an object SID to a sAMAccountName, or return the SID on failure."""
        try:
            self.conn.search(f'{self.dom_1}', f'(objectSID={sid})',
                             attributes=['sAMAccountName'])
            if self.conn.entries:
                return str(self.conn.entries[0].sAMAccountName)
        except Exception:
            pass
        return sid

    def _object_type_label(self, obj_classes: list) -> str:
        lc = [c.lower() for c in obj_classes]
        if 'computer' in lc:
            return 'Computer'
        if 'group' in lc:
            return 'Group'
        if 'msds-groupmanagedserviceaccount' in lc:
            return 'gMSA'
        return 'User'

    # ------------------------------------------------------------------
    # Resource Based Constrained Delegation
    # ------------------------------------------------------------------

    def rbcd_search(self):
        """
        Enumerate objects (computers AND users) that have
        msDS-AllowedToActOnBehalfOfOtherIdentity set and show which
        principals are allowed to delegate to them.
        """
        print_info('\n' + '-'*22 + 'Resource Based Constrained Delegation' + '-'*21 + '\n')
        print_info('[info] Querying computers and users for RBCD configurations...\n')

        self.conn.search(
            f'{self.dom_1}',
            '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'objectClass',
                        'msDS-AllowedToActOnBehalfOfOtherIdentity']
        )
        entries = list(self.conn.entries)

        out_path = os.path.join(self.dir_name, f'{self.domain}.rbcd.txt')
        if os.path.exists(out_path):
            os.remove(out_path)

        if not entries:
            msg = '  (no RBCD configurations found)'
            print_info(msg)
            with open(out_path, 'w') as f:
                f.write(msg + '\n')
            return

        out_lines = []
        for entry in entries:
            target      = str(entry.sAMAccountName)
            obj_type    = self._object_type_label(entry['objectClass'].values)
            raw_sd      = entry['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values[0]

            try:
                sd = SR_SECURITY_DESCRIPTOR(data=raw_sd)
            except Exception as e:
                print_error(f'  Could not parse SD for {target}: {e}')
                continue

            header = f'[{obj_type}] {target}  <-- can be delegated to by:'
            print_success(header)
            out_lines.append(header)

            if not sd['Dacl']:
                line = '  (empty DACL)'
                print_info(line)
                out_lines.append(line)
                continue

            for ace in sd['Dacl']['Data']:
                try:
                    sid            = ace['Ace']['Sid'].formatCanonical()
                    delegator_name = self._resolve_sid(sid)
                    # Determine the delegator's object type
                    self.conn.search(f'{self.dom_1}',
                                     f'(objectSID={sid})',
                                     attributes=['objectClass'])
                    d_type = 'Unknown'
                    if self.conn.entries:
                        d_type = self._object_type_label(
                            self.conn.entries[0]['objectClass'].values)
                    line = f'  -> [{d_type}] {delegator_name}  (SID: {sid})'
                    print_info(line)
                    out_lines.append(line)
                except Exception:
                    pass

        with open(out_path, 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write('\n'.join(out_lines) + '\n')

    # ------------------------------------------------------------------
    # DACL Enumeration
    # ------------------------------------------------------------------

    def dacl_search(self):
        """
        Pull the nTSecurityDescriptor for objects in the domain and report
        ACEs that grant dangerous rights to non-default principals.

        Behaviour depends on self.dacl and self.dacl_type:

          --dacl                         → all users, computers, and groups
          --dacl --dacl-type computer    → all computers only
          --dacl K2ROOTDC$               → that one object (any class)
          --dacl K2ROOTDC$ --dacl-type computer → that object, verified as a computer
          --dacl jdoe --dacl-type user   → that object, verified as a user

        Rights checked:
          GenericAll, GenericWrite, WriteOwner, WriteDACL,
          ForceChangePassword, AddMember, AddSelf, WriteSPN.
        """
        target_name = None if self.dacl == '__all__' else self.dacl
        type_filter = self.dacl_type   # 'user' | 'computer' | 'group' | None

        # ── Build a human-readable description for the banner ──────────────
        if target_name:
            scope_label = f'target: {target_name}'
            if type_filter:
                scope_label += f'  (type: {type_filter})'
        elif type_filter:
            scope_label = f'all {type_filter}s'
        else:
            scope_label = 'all users, computers, and groups'

        print_info('\n' + '-'*22 + 'DACL - Dangerous ACE Enumeration' + '-'*26 + '\n')
        print_info(f'[info] Scope → {scope_label}\n')

        # ── Build the object-class sub-filter ──────────────────────────────
        _type_clause = {
            'user':     '(&(objectClass=user)(objectCategory=Person)(!(objectClass=computer)))',
            'computer': '(&(objectClass=computer)(!(objectClass=msDS-ManagedServiceAccount)))',
            'group':    '(objectClass=group)',
        }

        if type_filter:
            class_filter = _type_clause[type_filter]
        else:
            # No type specified — search all three classes
            class_filter = (
                '(|'
                '(&(objectClass=user)(objectCategory=Person)(!(objectClass=computer)))'
                '(&(objectClass=computer)(!(objectClass=msDS-ManagedServiceAccount)))'
                '(objectClass=group)'
                ')'
            )

        # ── Add sAMAccountName constraint when a specific target is given ──
        if target_name:
            ldap_filter = f'(&(sAMAccountName={target_name}){class_filter})'
        else:
            ldap_filter = class_filter

        # ── Execute the search ─────────────────────────────────────────────
        sd_ctrl = security_descriptor_control(sdflags=0x04)
        self.conn.search(
            f'{self.dom_1}',
            ldap_filter,
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'objectClass', 'nTSecurityDescriptor'],
            controls=sd_ctrl
        )
        objects = list(self.conn.entries)

        # ── Bail out early when a named target was not found ──────────────
        if target_name and not objects:
            if type_filter:
                print_error(f'[error] No {type_filter} found with sAMAccountName: {target_name}')
            else:
                print_error(f'[error] No object found with sAMAccountName: {target_name}')
            return

        print_info(f'[info] Analysing {len(objects)} object(s)...\n')

        # ── Determine output filename ──────────────────────────────────────
        if target_name:
            # Sanitise the name so it's safe as a filename component
            safe_name = re.sub(r'[^\w\-]', '_', target_name)
            out_path = os.path.join(self.dir_name, f'{self.domain}.dacl.{safe_name}.txt')
        elif type_filter:
            out_path = os.path.join(self.dir_name, f'{self.domain}.dacl.{type_filter}s.txt')
        else:
            out_path = os.path.join(self.dir_name, f'{self.domain}.dacl.txt')

        if os.path.exists(out_path):
            os.remove(out_path)

        findings = []

        for obj in objects:
            obj_name = str(obj.sAMAccountName)
            obj_label = self._object_type_label(obj['objectClass'].values)

            raw_sd_list = obj['nTSecurityDescriptor'].raw_values
            if not raw_sd_list:
                continue
            try:
                sd = SR_SECURITY_DESCRIPTOR(data=raw_sd_list[0])
            except Exception:
                continue
            if not sd['Dacl']:
                continue

            obj_findings = []

            for ace in sd['Dacl']['Data']:
                try:
                    ace_type  = ace['AceType']
                    if ace_type not in (_ACE_TYPE_ACCESS_ALLOWED,
                                        _ACE_TYPE_ACCESS_ALLOWED_OBJECT):
                        continue

                    ace_inner   = ace['Ace']
                    mask        = ace_inner['Mask']['Mask']
                    trustee_sid = ace_inner['Sid'].formatCanonical()
                    trustee     = self._resolve_sid(trustee_sid)

                    if trustee.lower() in _SKIP_TRUSTEES:
                        continue
                    if trustee.lower() == obj_name.lower():
                        continue

                    rights = []

                    if ace_type == _ACE_TYPE_ACCESS_ALLOWED:
                        if mask & _ACE_GENERIC_ALL:
                            rights.append('GenericAll')
                        if mask & _ACE_GENERIC_WRITE:
                            rights.append('GenericWrite')
                        if mask & _ACE_WRITE_OWNER:
                            rights.append('WriteOwner')
                        if mask & _ACE_WRITE_DACL:
                            rights.append('WriteDACL')
                        if mask & _ACE_DS_WRITE_PROP:
                            rights.append('WriteProperty(All)')

                    elif ace_type == _ACE_TYPE_ACCESS_ALLOWED_OBJECT:
                        flags            = ace_inner.get('Flags', 0)
                        obj_type_present = flags & 0x1

                        if obj_type_present:
                            guid    = self._guid_bytes_to_str(ace_inner['ObjectType'])
                            guid_lc = guid.lower()

                            if mask & _ACE_DS_CONTROL_ACCESS and guid_lc == _GUID_FORCE_CHANGE_PW:
                                rights.append('ForceChangePassword')
                            elif mask & _ACE_DS_WRITE_PROP and guid_lc == _GUID_MEMBER_ATTR:
                                rights.append('AddMember(WriteProperty:member)')
                            elif mask & _ACE_DS_SELF and guid_lc == _GUID_MEMBER_ATTR:
                                rights.append('AddSelf(member)')
                            elif mask & _ACE_DS_WRITE_PROP and guid_lc == _GUID_SPN_ATTR:
                                rights.append('WriteSPN(servicePrincipalName)')
                            elif mask & _ACE_DS_WRITE_PROP and guid_lc == _GUID_RBCD_ATTR:
                                rights.append('WriteRBCD(msDS-AllowedToActOnBehalfOfOtherIdentity)')
                            elif mask & _ACE_GENERIC_ALL:
                                rights.append(f'GenericAll(ObjectType:{guid})')
                            elif mask & _ACE_GENERIC_WRITE:
                                rights.append(f'GenericWrite(ObjectType:{guid})')
                            elif mask & _ACE_WRITE_OWNER:
                                rights.append(f'WriteOwner(ObjectType:{guid})')
                            elif mask & _ACE_WRITE_DACL:
                                rights.append(f'WriteDACL(ObjectType:{guid})')
                        else:
                            if mask & _ACE_GENERIC_ALL:
                                rights.append('GenericAll')
                            if mask & _ACE_GENERIC_WRITE:
                                rights.append('GenericWrite')
                            if mask & _ACE_WRITE_OWNER:
                                rights.append('WriteOwner')
                            if mask & _ACE_WRITE_DACL:
                                rights.append('WriteDACL')

                    if rights:
                        right_str = ', '.join(rights)
                        line = (f'  [{obj_label}] {obj_name}'
                                f'  <--  [{right_str}]'
                                f'  granted to: {trustee}'
                                f'  (SID: {trustee_sid})')
                        obj_findings.append(line)

                except Exception:
                    continue

            if obj_findings:
                header = f'\n[*] {obj_name} ({obj_label})'
                print_success(header)
                findings.append(header)
                for line in obj_findings:
                    print_info(line)
                    findings.append(line)

        if not findings:
            msg = '  (no dangerous ACEs found outside of default admin trustees)'
            print_info(msg)
            findings.append(msg)

        with open(out_path, 'w') as f:
            f.write(f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n# {'─'*60}\n")
            f.write('\n'.join(findings) + '\n')

        total = sum(1 for l in findings if '<--' in l)
        print_info(f'\n[info] DACL enumeration complete. '
                   f'{total} dangerous ACE(s) found.')


    # ======================================================================
    # VULNERABILITY / SECURITY CHECK HELPERS
    # ======================================================================

    def _get_domain_sid(self) -> str:
        """Return the domain SID string (e.g. S-1-5-21-...) from the domain NC head."""
        self.conn.search(self.dom_1, '(objectClass=domain)',
                         search_scope=SUBTREE, attributes=['objectSid'])
        if not self.conn.entries:
            return ''
        raw = self.conn.entries[0]['objectSid'].raw_values
        if not raw:
            return ''
        return str(self.conn.entries[0]['objectSid'].value)

    def _sid_is_privileged(self, sid: str, domain_sid: str) -> bool:
        """Return True if the SID belongs to a well-known privileged group."""
        if sid in _PRIV_BUILTIN_SIDS:
            return True
        if domain_sid:
            for rid in _PRIV_RIDS:
                if sid == f'{domain_sid}-{rid}':
                    return True
        return False

    def _resolve_sid_to_name(self, sid: str) -> str:
        """Attempt to resolve a SID string to a sAMAccountName; fall back to the SID."""
        try:
            self.conn.search(self.dom_1,
                             f'(objectSid={sid})',
                             search_scope=SUBTREE,
                             attributes=['sAMAccountName'])
            if self.conn.entries:
                name = str(self.conn.entries[0]['sAMAccountName'].value)
                if name:
                    return name
        except Exception:
            pass
        return sid

    def _parse_sd_raw(self, raw_sd: bytes) -> list:
        """
        Minimal binary ACL parser.  Returns a list of dicts with keys:
          ace_type, access_mask, object_type (str GUID or None), trustee_sid (str).
        """
        aces = []
        if not raw_sd or len(raw_sd) < 20:
            return aces
        try:
            revision, sbz1, control, off_owner, off_group, off_sacl, off_dacl = (
                struct.unpack_from('<BBHIIII', raw_sd, 0))
            if off_dacl == 0:
                return aces
            acl_rev, _, acl_size, ace_count, _ = struct.unpack_from('<BBHHH', raw_sd, off_dacl)
            offset = off_dacl + 8
            for _ in range(ace_count):
                if offset + 4 > len(raw_sd):
                    break
                ace_type, ace_flags, ace_size = struct.unpack_from('<BBH', raw_sd, offset)
                ace_data = raw_sd[offset:offset + ace_size]
                access_mask = struct.unpack_from('<I', ace_data, 4)[0] if len(ace_data) >= 8 else 0
                object_type = None
                sid_offset = 8
                if ace_type in (0x05, 0x06, 0x07, 0x08):
                    obj_flags = struct.unpack_from('<I', ace_data, 8)[0] if len(ace_data) >= 12 else 0
                    sid_offset = 12
                    if obj_flags & 0x1:
                        if len(ace_data) >= sid_offset + 16:
                            b = ace_data[sid_offset:sid_offset + 16]
                            object_type = (
                                f'{int.from_bytes(b[0:4],"little"):08x}-'
                                f'{int.from_bytes(b[4:6],"little"):04x}-'
                                f'{int.from_bytes(b[6:8],"little"):04x}-'
                                f'{b[8:10].hex()}-{b[10:16].hex()}'
                            )
                            sid_offset += 16
                        if obj_flags & 0x2:
                            sid_offset += 16
                if sid_offset + 8 <= len(ace_data):
                    sr = ace_data[sid_offset]
                    sub_count = ace_data[sid_offset + 1]
                    authority = int.from_bytes(ace_data[sid_offset + 2:sid_offset + 8], 'big')
                    subs = []
                    for i in range(sub_count):
                        so = sid_offset + 8 + i * 4
                        if so + 4 <= len(ace_data):
                            subs.append(struct.unpack_from('<I', ace_data, so)[0])
                    sid = f'S-{sr}-{authority}-' + '-'.join(str(s) for s in subs)
                    aces.append({'ace_type': ace_type, 'access_mask': access_mask,
                                 'object_type': object_type, 'trustee_sid': sid})
                offset += ace_size
        except Exception:
            pass
        return aces

    def _fetch_sd(self, base_dn: str, ldap_filter: str = '(objectClass=*)',
                  scope=None, extra_attrs: list = None) -> list:
        """Search for nTSecurityDescriptor + extra_attrs.  Returns conn.entries."""
        if scope is None:
            scope = SUBTREE
        attrs = (extra_attrs or []) + ['nTSecurityDescriptor']
        ctrl = security_descriptor_control(sdflags=0x04)
        try:
            self.conn.search(search_base=base_dn, search_filter=ldap_filter,
                             search_scope=scope, attributes=attrs, controls=ctrl)
        except Exception as e:
            print_error(f'  [!] _fetch_sd failed ({base_dn[:60]}): {e}')
        return list(self.conn.entries)

    def _write_results(self, filename: str, lines: list) -> str:
        """Write lines to <domain_dir>/<filename>.txt with a timestamp header."""
        path = os.path.join(self.dir_name, f'{self.domain}.{filename}.txt')
        if os.path.exists(path):
            os.remove(path)
        header = (
            f"# adLDAP  |  {self.domain}  |  {self.run_ts}\n"
            f"# {'─' * 60}\n"
        )
        with open(path, 'w') as fh:
            fh.write(header + '\n'.join(lines) + '\n')
        return path

    # ------------------------------------------------------------------
    # 1. AdminSDHolder ACL
    # ------------------------------------------------------------------
    def check_adminsdholder(self):
        """
        Inspect the AdminSDHolder object ACL for unexpected write permissions.
        SDProp propagates this ACL to all protected accounts every 60 minutes,
        making a backdoor ACE here extremely persistent.
        """
        print('\n' + '-' * 22 + 'AdminSDHolder ACL Inspection' + '-' * 30 + '\n')
        domain_sid = self._get_domain_sid()
        dn = f'CN=AdminSDHolder,CN=System,{self.dom_1}'
        entries = self._fetch_sd(dn, '(objectClass=*)', scope=BASE)
        if not entries:
            print_error('  [!] AdminSDHolder object not readable.')
            return

        sd_raw = entries[0]['nTSecurityDescriptor'].raw_values
        if not sd_raw:
            print_error('  [!] No security descriptor returned.')
            return

        risky = []
        for ace in self._parse_sd_raw(sd_raw[0]):
            if ace['ace_type'] not in (0x00, 0x05):
                continue
            sid = ace['trustee_sid']
            mask = ace['access_mask']
            if self._sid_is_privileged(sid, domain_sid):
                continue
            if mask & (_ACE_GENERIC_ALL | _ACE_WRITE_DACL | _ACE_WRITE_OWNER |
                       _ACE_GENERIC_WRITE | _ACE_DS_WRITE_PROP):
                name = self._resolve_sid_to_name(sid)
                risky.append(f'  {name} (SID: {sid})  mask: 0x{mask:08x}')

        lines = [f'AdminSDHolder ACL — {self.domain}']
        if risky:
            print_error(f'  [!] {len(risky)} non-privileged principal(s) with write access on AdminSDHolder:')
            lines.append(f'[CRITICAL] {len(risky)} unexpected write ACE(s) found — SDProp will push these to ALL protected objects.')
            for r in risky:
                print(Fore.RED + r + Style.RESET_ALL)
                lines.append(r)
            lines.append('')
            lines.append('Remediation: Remove unexpected ACEs immediately.')
            lines.append('  PowerShell: (Get-Acl "AD:CN=AdminSDHolder,CN=System,...").Access | Where {<filter>} | ForEach {Remove-ADPermission ...}')
        else:
            print_success('  [+] AdminSDHolder ACL looks clean — no unexpected write permissions found.')
            lines.append('[OK] No unexpected write ACEs found.')

        path = self._write_results('adminsdholder', lines)


    # ------------------------------------------------------------------
    # 2. SID History Abuse
    # ------------------------------------------------------------------
    def check_sid_history(self):
        """
        Find accounts with privileged SIDs in sIDHistory.
        These accounts hold DA-equivalent privileges without appearing in any group.
        """
        print('\n' + '-' * 22 + 'SID History Abuse' + '-' * 41 + '\n')
        domain_sid = self._get_domain_sid()

        self.conn.search(self.dom_1,
                         '(&(|(objectClass=user)(objectClass=computer))(sIDHistory=*))',
                         search_scope=SUBTREE,
                         attributes=['sAMAccountName', 'sIDHistory', 'objectClass'])
        results = list(self.conn.entries)

        lines = [f'SID History Abuse — {self.domain}']
        priv_hits, normal_hits = [], []

        for obj in results:
            name = str(obj['sAMAccountName'].value)
            sids = obj['sIDHistory'].values if hasattr(obj['sIDHistory'], 'values') else []
            for sid_val in sids:
                sid_str = str(sid_val)
                if self._sid_is_privileged(sid_str, domain_sid):
                    priv_hits.append(f'  [PRIVILEGED] {name} -> {sid_str}')
                else:
                    normal_hits.append(f'  {name} -> {sid_str}')

        if not results:
            print_success('  [+] No accounts with sIDHistory found.')
            lines.append('[OK] No accounts have sIDHistory populated.')
        else:
            if priv_hits:
                print_error(f'  [CRITICAL] {len(priv_hits)} account(s) carry PRIVILEGED SIDs in sIDHistory:')
                lines.append(f'[CRITICAL] {len(priv_hits)} account(s) with privileged SID history:')
                for h in priv_hits:
                    print(Fore.RED + h + Style.RESET_ALL)
                    lines.append(h)
                lines.append('')
                lines.append('Remediation: Set-ADUser <user> -Remove @{sIDHistory="<SID>"}')
                lines.append('Enable SID filtering on all trusts: netdom trust /domain:<remote> /EnableSIDHistory:no')
            if normal_hits:
                print_info(f'  [info] {len(normal_hits)} account(s) with non-privileged sIDHistory entries:')
                lines.append(f'\n[INFO] {len(normal_hits)} non-privileged SID history entries (may be migration artefacts):')
                for h in normal_hits[:30]:
                    print(h)
                    lines.append(h)

        path = self._write_results('sid_history', lines)


    # ------------------------------------------------------------------
    # 3. Shadow Credentials
    # ------------------------------------------------------------------
    def check_shadow_credentials(self):
        """
        Find accounts with msDS-KeyCredentialLink set (Shadow Credentials).
        An attacker who adds their own entry here can authenticate as the account
        via PKINIT without knowing the password.
        """
        print('\n' + '-' * 22 + 'Shadow Credentials (msDS-KeyCredentialLink)' + '-' * 15 + '\n')

        self.conn.search(self.dom_1,
                         '(&(objectClass=user)(msDS-KeyCredentialLink=*))',
                         search_scope=SUBTREE,
                         attributes=['sAMAccountName', 'msDS-KeyCredentialLink', 'adminCount'])
        users = list(self.conn.entries)
        self.conn.search(self.dom_1,
                         '(&(objectClass=computer)(msDS-KeyCredentialLink=*))',
                         search_scope=SUBTREE,
                         attributes=['sAMAccountName', 'msDS-KeyCredentialLink'])
        computers = list(self.conn.entries)

        lines = [f'Shadow Credentials — {self.domain}']
        admin_hits, user_hits, comp_hits = [], [], []

        for u in users:
            name = str(u['sAMAccountName'].value)
            count = len(u['msDS-KeyCredentialLink'].values) if hasattr(u['msDS-KeyCredentialLink'], 'values') else 1
            is_admin = int(u['adminCount'].value or 0) == 1
            entry = f'  {name}  ({count} key credential(s))'
            (admin_hits if is_admin else user_hits).append(entry)

        for c in computers:
            name = str(c['sAMAccountName'].value)
            count = len(c['msDS-KeyCredentialLink'].values) if hasattr(c['msDS-KeyCredentialLink'], 'values') else 1
            comp_hits.append(f'  {name}  ({count} key credential(s))')

        if not users and not computers:
            print_success('  [+] No msDS-KeyCredentialLink entries found.')
            lines.append('[OK] No shadow credential entries detected.')
        else:
            if admin_hits:
                print_error(f'  [CRITICAL] {len(admin_hits)} PRIVILEGED account(s) have shadow credentials:')
                lines.append(f'[CRITICAL] Privileged accounts with msDS-KeyCredentialLink:')
                for h in admin_hits:
                    print(Fore.RED + h + Style.RESET_ALL)
                    lines.append(h)
                lines.append('')
                lines.append('Remediation: Set-ADUser <user> -Clear msDS-KeyCredentialLink')
            if user_hits:
                print_info(f'  [!] {len(user_hits)} user account(s) with shadow credentials:')
                lines.append(f'\n[HIGH] User accounts with msDS-KeyCredentialLink:')
                for h in user_hits:
                    print(h)
                    lines.append(h)
            if comp_hits:
                print_info(f'  [!] {len(comp_hits)} computer account(s) with shadow credentials:')
                lines.append(f'\n[INFO] Computer accounts with msDS-KeyCredentialLink (may be legitimate WHfB):')
                for h in comp_hits:
                    print(h)
                    lines.append(h)

        path = self._write_results('shadow_credentials', lines)


    # ------------------------------------------------------------------
    # 4. Foreign Security Principals in Privileged Groups
    # ------------------------------------------------------------------
    def check_foreign_principals(self):
        """
        Find Foreign Security Principals (objects from trusted domains) that
        are direct members of sensitive privileged groups.
        """
        print('\n' + '-' * 22 + 'Foreign Security Principals in Privileged Groups' + '-' * 10 + '\n')

        sensitive_groups = {
            'Domain Admins':              f'CN=Domain Admins,CN=Users,{self.dom_1}',
            'Enterprise Admins':          f'CN=Enterprise Admins,CN=Users,{self.dom_1}',
            'Schema Admins':              f'CN=Schema Admins,CN=Users,{self.dom_1}',
            'Administrators':             f'CN=Administrators,CN=Builtin,{self.dom_1}',
            'Account Operators':          f'CN=Account Operators,CN=Builtin,{self.dom_1}',
            'Backup Operators':           f'CN=Backup Operators,CN=Builtin,{self.dom_1}',
            'Server Operators':           f'CN=Server Operators,CN=Builtin,{self.dom_1}',
            'Group Policy Creator Owners':f'CN=Group Policy Creator Owners,CN=Users,{self.dom_1}',
        }

        fsp_base = f'CN=ForeignSecurityPrincipals,{self.dom_1}'
        self.conn.search(fsp_base, '(objectClass=foreignSecurityPrincipal)',
                         search_scope=SUBTREE, attributes=['cn', 'memberOf'])
        fsps = list(self.conn.entries)

        hits = []
        for fsp in fsps:
            sid = str(fsp['cn'].value)
            groups = fsp['memberOf'].values if hasattr(fsp['memberOf'], 'values') else []
            for gdn in groups:
                for gname, sens_dn in sensitive_groups.items():
                    if str(gdn).lower() == sens_dn.lower():
                        resolved = self._resolve_sid_to_name(sid)
                        hits.append(f'  {resolved} (SID: {sid})  ->  {gname}')

        lines = [f'Foreign Security Principals in Privileged Groups — {self.domain}']
        if hits:
            print_error(f'  [CRITICAL] {len(hits)} Foreign Security Principal(s) in privileged groups:')
            lines.append(f'[CRITICAL] {len(hits)} FSP(s) found in sensitive groups:')
            for h in hits:
                print(Fore.RED + h + Style.RESET_ALL)
                lines.append(h)
            lines.append('')
            lines.append('Remediation: Remove FSPs from privileged groups unless there is an explicit business requirement.')
            lines.append('Enable selective authentication on trusts to limit cross-domain access.')
        else:
            print_success('  [+] No Foreign Security Principals found in privileged groups.')
            lines.append('[OK] No FSPs detected in privileged groups.')

        path = self._write_results('foreign_principals', lines)


    # ------------------------------------------------------------------
    # 5. Dangerous Constrained Delegation Targets
    # ------------------------------------------------------------------
    def check_dangerous_delegation(self):
        """
        Find accounts delegating to sensitive services (ldap/cifs/host/gc/krbtgt)
        on Domain Controllers.  Compromising any such account enables full DA.
        """
        print('\n' + '-' * 22 + 'Dangerous Constrained Delegation Targets' + '-' * 18 + '\n')

        # Collect DC hostnames / short names
        self.conn.search(self.dom_1,
                         '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                         search_scope=SUBTREE,
                         attributes=['dNSHostName', 'sAMAccountName'])
        dc_names = set()
        for dc in self.conn.entries:
            h = str(dc['dNSHostName'].value or '').lower()
            s = str(dc['sAMAccountName'].value or '').lower().rstrip('$')
            if h: dc_names.add(h)
            if s: dc_names.add(s)

        # All objects with msDS-AllowedToDelegateTo
        self.conn.search(self.dom_1, '(msDS-AllowedToDelegateTo=*)',
                         search_scope=SUBTREE,
                         attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo', 'adminCount'])
        delegating = list(self.conn.entries)

        hits = []
        for obj in delegating:
            name = str(obj['sAMAccountName'].value)
            targets = obj['msDS-AllowedToDelegateTo'].values if hasattr(obj['msDS-AllowedToDelegateTo'], 'values') else []
            is_admin = int(obj['adminCount'].value or 0) == 1
            for tgt in targets:
                tgt_lower = str(tgt).lower()
                svc = tgt_lower.split('/')[0] + '/' if '/' in tgt_lower else ''
                host_short = tgt_lower.split('/')[1].split(':')[0].split('.')[0] if '/' in tgt_lower else ''
                if (any(tgt_lower.startswith(p) for p in _DANGEROUS_SVC_PREFIXES) and
                        host_short in dc_names):
                    tag = ' [ADMIN-SOURCE]' if is_admin else ''
                    hits.append(f'  {name}{tag}  ->  {tgt}  [DC + sensitive SPN]')

        lines = [f'Dangerous Constrained Delegation Targets — {self.domain}']
        if hits:
            print_error(f'  [CRITICAL] {len(hits)} dangerous delegation target(s) found:')
            lines.append(f'[CRITICAL] {len(hits)} account(s) delegate to sensitive DC services:')
            for h in hits:
                print(Fore.RED + h + Style.RESET_ALL)
                lines.append(h)
            lines.append('')
            lines.append('Remediation: Remove delegation to LDAP/CIFS/HOST/GC/KRBTGT on DCs.')
            lines.append('Prefer RBCD with minimal scope over broad constrained delegation.')
        else:
            print_success('  [+] No dangerous constrained delegation targets found.')
            lines.append('[OK] No accounts delegate to sensitive services on Domain Controllers.')

        path = self._write_results('dangerous_delegation', lines)


    # ------------------------------------------------------------------
    # 6. RBCD on Domain Object / DC Objects
    # ------------------------------------------------------------------
    def check_rbcd_on_domain(self):
        """
        Check if msDS-AllowedToActOnBehalfOfOtherIdentity is set on:
          - The domain NC head (catastrophic — any user in the ACL is effectively DA)
          - Any Domain Controller computer object
        """
        print('\n' + '-' * 22 + 'RBCD on Domain / DC Objects' + '-' * 31 + '\n')
        lines = [f'RBCD on Domain / DC Objects — {self.domain}']

        # --- Domain object ---
        self.conn.search(self.dom_1, '(objectClass=domain)',
                         search_scope=SUBTREE,
                         attributes=['msDS-AllowedToActOnBehalfOfOtherIdentity', 'distinguishedName'])
        dom_hits = list(self.conn.entries)
        found_domain_rbcd = False
        for dom in dom_hits:
            raw = dom['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values
            if not raw or not raw[0]:
                continue
            found_domain_rbcd = True
            trustees = []
            for ace in self._parse_sd_raw(raw[0]):
                if ace['ace_type'] == 0x00:
                    trustees.append('  ' + self._resolve_sid_to_name(ace['trustee_sid']))
            print_error('  [CRITICAL] RBCD is set on the domain NC head object!')
            print_error('  Any principal in the RBCD ACL can impersonate ANY domain user to ANY service.')
            lines.append('[CRITICAL] msDS-AllowedToActOnBehalfOfOtherIdentity set on the DOMAIN OBJECT:')
            for t in trustees:
                print(Fore.RED + t + Style.RESET_ALL)
                lines.append(t)
            lines.append('Remediation: Set-ADObject (Get-ADDomain).DistinguishedName -Clear msDS-AllowedToActOnBehalfOfOtherIdentity')

        if not found_domain_rbcd:
            print_success('  [+] Domain NC head: no RBCD configured.')
            lines.append('[OK] No RBCD on the domain object.')

        # --- DC computer objects ---
        self.conn.search(self.dom_1,
                         '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)'
                         '(msDS-AllowedToActOnBehalfOfOtherIdentity=*))',
                         search_scope=SUBTREE,
                         attributes=['sAMAccountName', 'dNSHostName'])
        dc_hits = list(self.conn.entries)
        if dc_hits:
            print_error(f'  [CRITICAL] {len(dc_hits)} DC(s) have RBCD set:')
            lines.append(f'\n[CRITICAL] {len(dc_hits)} Domain Controller(s) with RBCD configured:')
            for dc in dc_hits:
                name = str(dc['dNSHostName'].value or dc['sAMAccountName'].value)
                print(Fore.RED + f'  {name}' + Style.RESET_ALL)
                lines.append(f'  {name}')
            lines.append('Remediation: Get-ADComputer -Filter {{PrimaryGroupID -eq 516}} | Set-ADComputer -Clear msDS-AllowedToActOnBehalfOfOtherIdentity')
        else:
            print_success('  [+] No DC computer objects have RBCD configured.')
            lines.append('[OK] No DCs have RBCD configured.')

        path = self._write_results('rbcd_domain', lines)


    # ------------------------------------------------------------------
    # 7. Indirect Privileged Group Membership (transitive nesting)
    # ------------------------------------------------------------------
    def check_indirect_admins(self):
        """
        Find user accounts that are transitive members of privileged groups
        but NOT direct members.  These are often overlooked during access reviews.
        """
        print('\n' + '-' * 22 + 'Indirect Privileged Group Membership' + '-' * 22 + '\n')

        priv_groups = {
            'Domain Admins':   f'CN=Domain Admins,CN=Users,{self.dom_1}',
            'Enterprise Admins': f'CN=Enterprise Admins,CN=Users,{self.dom_1}',
            'Administrators':  f'CN=Administrators,CN=Builtin,{self.dom_1}',
            'Schema Admins':   f'CN=Schema Admins,CN=Users,{self.dom_1}',
            'Backup Operators':f'CN=Backup Operators,CN=Builtin,{self.dom_1}',
            'Account Operators':f'CN=Account Operators,CN=Builtin,{self.dom_1}',
        }

        lines = [f'Indirect Privileged Group Membership — {self.domain}']
        total_indirect = 0

        for gname, gdn in priv_groups.items():
            # Transitive members (LDAP_MATCHING_RULE_IN_CHAIN)
            self.conn.search(self.dom_1,
                             f'(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={gdn}))',
                             search_scope=SUBTREE, attributes=['sAMAccountName', 'memberOf'])
            transitive = {str(e['sAMAccountName'].value): e for e in self.conn.entries}

            # Direct members
            self.conn.search(self.dom_1,
                             f'(&(objectClass=user)(memberOf={gdn}))',
                             search_scope=SUBTREE, attributes=['sAMAccountName'])
            direct = {str(e['sAMAccountName'].value) for e in self.conn.entries}

            indirect = {n: e for n, e in transitive.items() if n not in direct}
            if not indirect:
                continue

            total_indirect += len(indirect)
            print_info(f'  [!] {gname}: {len(indirect)} indirect member(s)')
            lines.append(f'\n[{gname}] {len(indirect)} transitive-only member(s):')
            for name in sorted(indirect.keys()):
                line = f'  {name}'
                print(line)
                lines.append(line)

        if total_indirect == 0:
            print_success('  [+] No unexpected indirect privileged group memberships found.')
            lines.append('[OK] No indirect privileged group memberships detected.')
        else:
            lines.append(f'\nTotal: {total_indirect} indirect membership(s) found.')
            lines.append('Remediation: Review nested group chains and flatten where possible.')

        path = self._write_results('indirect_admins', lines)


    # ------------------------------------------------------------------
    # 8. DCSync Rights
    # ------------------------------------------------------------------
    def check_dcsync(self):
        """
        Find non-privileged principals that have DS-Replication-Get-Changes-All
        (or related replication rights) on the domain object.  These accounts
        can dump all password hashes without being a Domain Admin.
        """
        print('\n' + '-' * 22 + 'DCSync Rights on Non-Privileged Principals' + '-' * 17 + '\n')
        domain_sid = self._get_domain_sid()

        entries = self._fetch_sd(self.dom_1, '(objectClass=domain)',
                                 extra_attrs=['distinguishedName'])
        lines = [f'DCSync Rights — {self.domain}']
        hits: dict = {}

        for dom in entries:
            raw = dom['nTSecurityDescriptor'].raw_values
            if not raw:
                continue
            for ace in self._parse_sd_raw(raw[0]):
                if ace['ace_type'] != 0x05:
                    continue
                sid = ace['trustee_sid']
                otype = (ace['object_type'] or '').lower().strip()
                if self._sid_is_privileged(sid, domain_sid):
                    continue
                if otype in _REPL_GUID_NAMES:
                    name = self._resolve_sid_to_name(sid)
                    hits.setdefault(name, []).append(_REPL_GUID_NAMES[otype])

        if hits:
            print_error(f'  [CRITICAL] {len(hits)} non-privileged principal(s) have DCSync rights:')
            lines.append(f'[CRITICAL] {len(hits)} principal(s) with replication rights:')
            for name, rights in sorted(hits.items()):
                line = f'  {name}  ->  {", ".join(rights)}'
                print(Fore.RED + line + Style.RESET_ALL)
                lines.append(line)
            lines.append('')
            lines.append('Remediation: Remove DS-Replication-Get-Changes-All from non-DC/non-DA accounts immediately.')
        else:
            print_success('  [+] No unexpected DCSync rights found.')
            lines.append('[OK] No non-privileged principals have replication rights.')

        path = self._write_results('dcsync', lines)


    # ------------------------------------------------------------------
    # 9. Protected Users Group
    # ------------------------------------------------------------------
    def check_protected_users(self):
        """
        Report membership of the Protected Users group.
        Flag privileged accounts (adminCount=1) that are NOT in it.
        """
        print('\n' + '-' * 22 + 'Protected Users Group' + '-' * 37 + '\n')

        pu_dn = f'CN=Protected Users,CN=Users,{self.dom_1}'
        self.conn.search(self.dom_1,
                         f'(&(objectClass=user)(memberOf={pu_dn}))',
                         search_scope=SUBTREE, attributes=['sAMAccountName'])
        pu_members = {str(e['sAMAccountName'].value) for e in self.conn.entries}

        self.conn.search(self.dom_1,
                         '(&(objectClass=user)(!(objectClass=computer))(adminCount=1)'
                         '(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                         search_scope=SUBTREE, attributes=['sAMAccountName'])
        priv_users = [str(e['sAMAccountName'].value) for e in self.conn.entries]

        missing = [u for u in priv_users if u not in pu_members]
        lines = [f'Protected Users Group — {self.domain}']

        print_info(f'  [info] Protected Users members: {len(pu_members)}')
        lines.append(f'Protected Users members ({len(pu_members)}):')
        for m in sorted(pu_members):
            lines.append(f'  {m}')

        if missing:
            print_error(f'  [!] {len(missing)} privileged account(s) NOT in Protected Users:')
            lines.append(f'\n[HIGH] {len(missing)} privileged account(s) missing from Protected Users:')
            for u in missing:
                print(Fore.YELLOW + f'  {u}' + Style.RESET_ALL)
                lines.append(f'  {u}')
            lines.append('')
            lines.append('Remediation: Add all privileged accounts to the Protected Users group.')
            lines.append('  Add-ADGroupMember -Identity "Protected Users" -Members <accounts>')
        else:
            print_success('  [+] All privileged accounts are in the Protected Users group.')
            lines.append('\n[OK] All privileged accounts are in Protected Users.')

        path = self._write_results('protected_users', lines)


    # ------------------------------------------------------------------
    # 10. ADCS ESC4 — Writable Certificate Template ACLs
    # ------------------------------------------------------------------
    def check_adcs_esc4(self):
        """
        Find non-privileged principals with GenericAll / WriteDACL / WriteOwner /
        GenericWrite on any certificate template object.
        """
        print('\n' + '-' * 22 + 'ADCS ESC4 — Writable Certificate Template ACLs' + '-' * 11 + '\n')
        domain_sid = self._get_domain_sid()

        config_dn = self.conn.server.info.other.get('configurationNamingContext', [''])[0]
        if not config_dn:
            print_error('  [!] Cannot determine configuration naming context.')
            return
        tmpl_base = f'CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}'

        entries = self._fetch_sd(tmpl_base, '(objectClass=pKICertificateTemplate)',
                                 extra_attrs=['cn'])
        lines = [f'ADCS ESC4 — Writable Certificate Template ACLs — {self.domain}']
        by_trustee: dict = {}

        for tmpl in entries:
            tname = str(tmpl['cn'].value)
            raw = tmpl['nTSecurityDescriptor'].raw_values
            if not raw:
                continue
            for ace in self._parse_sd_raw(raw[0]):
                if ace['ace_type'] not in (0x00, 0x05):
                    continue
                sid = ace['trustee_sid']
                mask = ace['access_mask']
                if self._sid_is_privileged(sid, domain_sid):
                    continue
                if mask & (_ACE_GENERIC_ALL | _ACE_WRITE_DACL | _ACE_WRITE_OWNER | _ACE_GENERIC_WRITE):
                    name = self._resolve_sid_to_name(sid)
                    by_trustee.setdefault(name, set()).add(tname)

        if by_trustee:
            print_error(f'  [CRITICAL] {len(by_trustee)} non-privileged principal(s) can modify certificate templates:')
            lines.append(f'[CRITICAL] {len(by_trustee)} trustee(s) with write access to certificate templates:')
            for trustee, tmpls in sorted(by_trustee.items()):
                line = f'  {trustee}  ->  {", ".join(sorted(tmpls))}'
                print(Fore.RED + line + Style.RESET_ALL)
                lines.append(line)
            lines.append('')
            lines.append('Remediation: Remove GenericAll/WriteDACL/WriteOwner/GenericWrite from non-privileged accounts on templates.')
        else:
            print_success('  [+] No misconfigured certificate template ACLs found (ESC4 clean).')
            lines.append('[OK] No non-privileged write access on certificate templates.')

        path = self._write_results('adcs_esc4', lines)


    # ------------------------------------------------------------------
    # 11. ADCS ESC5 — Writable PKI Object ACLs
    # ------------------------------------------------------------------
    def check_adcs_esc5(self):
        """
        Find non-privileged principals with write access to any PKI container
        object (not just templates), e.g. the Enrollment Services container,
        NTAuthCertificates, or CA configuration objects.
        """
        print('\n' + '-' * 22 + 'ADCS ESC5 — Writable PKI Container ACLs' + '-' * 19 + '\n')
        domain_sid = self._get_domain_sid()

        config_dn = self.conn.server.info.other.get('configurationNamingContext', [''])[0]
        if not config_dn:
            print_error('  [!] Cannot determine configuration naming context.')
            return
        pki_base = f'CN=Public Key Services,CN=Services,{config_dn}'

        entries = self._fetch_sd(pki_base, '(objectClass=*)', extra_attrs=['cn', 'distinguishedName'])
        lines = [f'ADCS ESC5 — Writable PKI Container ACLs — {self.domain}']
        by_trustee: dict = {}

        for obj in entries:
            oname = str(obj['cn'].value or obj['distinguishedName'].value or '')
            raw = obj['nTSecurityDescriptor'].raw_values
            if not raw:
                continue
            seen_sids: set = set()
            for ace in self._parse_sd_raw(raw[0]):
                if ace['ace_type'] not in (0x00, 0x05):
                    continue
                sid = ace['trustee_sid']
                mask = ace['access_mask']
                if self._sid_is_privileged(sid, domain_sid) or sid in seen_sids:
                    continue
                if mask & (_ACE_GENERIC_ALL | _ACE_WRITE_DACL | _ACE_WRITE_OWNER | _ACE_GENERIC_WRITE):
                    seen_sids.add(sid)
                    name = self._resolve_sid_to_name(sid)
                    by_trustee.setdefault(name, set()).add(oname)

        if by_trustee:
            print_error(f'  [CRITICAL] {len(by_trustee)} non-privileged principal(s) can modify PKI container objects:')
            lines.append(f'[CRITICAL] {len(by_trustee)} trustee(s) with write access to PKI objects:')
            for trustee, objs in sorted(by_trustee.items()):
                line = f'  {trustee}  ->  {", ".join(sorted(objs))}'
                print(Fore.RED + line + Style.RESET_ALL)
                lines.append(line)
            lines.append('')
            lines.append('Remediation: Remove write permissions from non-admin accounts on all PKI container objects.')
        else:
            print_success('  [+] No non-privileged write access on PKI container objects (ESC5 clean).')
            lines.append('[OK] No non-privileged write access on PKI container objects.')

        path = self._write_results('adcs_esc5', lines)


    # ------------------------------------------------------------------
    # 12. ADCS ESC7 — CA Officer / Manager Rights
    # ------------------------------------------------------------------
    def check_adcs_esc7(self):
        """
        Find non-privileged principals with CA Officer (ManageCertificates) or
        CA Manager (ManageCA) rights on Enrollment Service objects.
        These rights allow issuing arbitrary certificates.
        """
        print('\n' + '-' * 22 + 'ADCS ESC7 — CA Officer/Manager Rights' + '-' * 21 + '\n')
        domain_sid = self._get_domain_sid()
        CA_MANAGE = 0x00000001
        CA_OFFICER = 0x00000010

        config_dn = self.conn.server.info.other.get('configurationNamingContext', [''])[0]
        if not config_dn:
            print_error('  [!] Cannot determine configuration naming context.')
            return
        enroll_base = f'CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}'

        entries = self._fetch_sd(enroll_base, '(objectClass=pKIEnrollmentService)',
                                 extra_attrs=['cn'])
        lines = [f'ADCS ESC7 — CA Officer/Manager Rights — {self.domain}']
        by_trustee: dict = {}

        for ca in entries:
            cname = str(ca['cn'].value)
            raw = ca['nTSecurityDescriptor'].raw_values
            if not raw:
                continue
            for ace in self._parse_sd_raw(raw[0]):
                if ace['ace_type'] not in (0x00, 0x05):
                    continue
                sid = ace['trustee_sid']
                mask = ace['access_mask']
                if self._sid_is_privileged(sid, domain_sid):
                    continue
                if mask & (CA_MANAGE | CA_OFFICER | _ACE_GENERIC_ALL | _ACE_WRITE_DACL | _ACE_WRITE_OWNER):
                    name = self._resolve_sid_to_name(sid)
                    by_trustee.setdefault(name, []).append(cname)

        if by_trustee:
            print_error(f'  [CRITICAL] {len(by_trustee)} non-privileged principal(s) have CA Officer/Manager rights:')
            lines.append(f'[CRITICAL] {len(by_trustee)} principal(s) with CA management rights:')
            for trustee, cas in sorted(by_trustee.items()):
                line = f'  {trustee}  ->  CA: {", ".join(cas)}'
                print(Fore.RED + line + Style.RESET_ALL)
                lines.append(line)
            lines.append('')
            lines.append('Remediation: Remove ManageCertificates/ManageCA rights from non-admin accounts.')
        else:
            print_success('  [+] No non-privileged CA Officer/Manager rights found (ESC7 clean).')
            lines.append('[OK] No non-privileged CA Officer/Manager rights detected.')

        path = self._write_results('adcs_esc7', lines)


    # ------------------------------------------------------------------
    # 13. RC4 Kerberos Encryption
    # ------------------------------------------------------------------
    def check_rc4(self):
        """
        Find service accounts and DCs that still permit RC4-HMAC Kerberos tickets.
        RC4 hashes crack orders of magnitude faster than AES offline.
        """
        print('\n' + '-' * 22 + 'RC4 / Legacy Kerberos Encryption' + '-' * 26 + '\n')
        RC4_BIT = 0x04
        AES_BITS = 0x18  # AES128 | AES256

        # Service accounts with SPNs
        self.conn.search(self.dom_1,
                         '(&(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*)'
                         '(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                         search_scope=SUBTREE,
                         attributes=['sAMAccountName', 'msDS-SupportedEncryptionTypes', 'adminCount'])
        svc_accs = list(self.conn.entries)

        # Domain controllers
        self.conn.search(self.dom_1,
                         '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                         search_scope=SUBTREE,
                         attributes=['sAMAccountName', 'dNSHostName', 'msDS-SupportedEncryptionTypes'])
        dcs = list(self.conn.entries)

        svc_hits, dc_hits, admin_noaes = [], [], []

        for u in svc_accs:
            enc = int(u['msDS-SupportedEncryptionTypes'].value or 0)
            name = str(u['sAMAccountName'].value)
            is_admin = int(u['adminCount'].value or 0) == 1
            if enc == 0 or (enc & RC4_BIT):
                tag = ' [ADMIN]' if is_admin else ''
                svc_hits.append(f'  {name}{tag}  (encTypes=0x{enc:x})')

        for dc in dcs:
            enc = int(dc['msDS-SupportedEncryptionTypes'].value or 0)
            name = str(dc['dNSHostName'].value or dc['sAMAccountName'].value)
            if enc == 0 or (enc & RC4_BIT):
                dc_hits.append(f'  {name}  (encTypes=0x{enc:x})')

        lines = [f'RC4 / Legacy Kerberos Encryption — {self.domain}']

        if svc_hits:
            sev = 'CRITICAL' if any('[ADMIN]' in h for h in svc_hits) else 'HIGH'
            print_error(f'  [{sev}] {len(svc_hits)} service account(s) permit RC4 Kerberos encryption:')
            lines.append(f'[{sev}] Service accounts permitting RC4 ({len(svc_hits)}):')
            for h in svc_hits:
                print(Fore.RED + h + Style.RESET_ALL)
                lines.append(h)
            lines.append('Remediation: Set-ADUser <account> -KerberosEncryptionType AES128,AES256')
        else:
            print_success('  [+] No service accounts permitting RC4 found.')
            lines.append('[OK] No service accounts with RC4 encryption type.')

        if dc_hits:
            print_info(f'  [!] {len(dc_hits)} DC(s) permit RC4 Kerberos encryption:')
            lines.append(f'\n[MEDIUM] DCs permitting RC4 ({len(dc_hits)}):')
            for h in dc_hits:
                print(Fore.YELLOW + h + Style.RESET_ALL)
                lines.append(h)
            lines.append('Remediation: Configure "Network Security: Configure encryption types allowed for Kerberos" GPO to require AES only.')
        else:
            print_success('  [+] No DCs permitting RC4-only Kerberos found.')
            lines.append('[OK] No DCs with RC4-only Kerberos encryption.')

        path = self._write_results('rc4_kerberos', lines)


    # ------------------------------------------------------------------
    # 14. Pre-Windows 2000 Compatible Access Group
    # ------------------------------------------------------------------
    def check_pre_win2k(self):
        """
        Check if the Pre-Windows 2000 Compatible Access group contains
        Everyone (S-1-1-0) or Anonymous Logon (S-1-5-7).
        Either condition allows unauthenticated enumeration of AD via SAMR/LSARPC.
        """
        print('\n' + '-' * 22 + 'Pre-Windows 2000 Compatible Access Group' + '-' * 18 + '\n')

        pre2k_dn = f'CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{self.dom_1}'
        self.conn.search(self.dom_1,
                         f'(distinguishedName={pre2k_dn})',
                         search_scope=SUBTREE, attributes=['member'])
        grp = list(self.conn.entries)

        lines = [f'Pre-Windows 2000 Compatible Access Group — {self.domain}']
        if not grp:
            print_error('  [!] Could not locate the Pre-Windows 2000 Compatible Access group.')
            lines.append('[INFO] Group not found.')
            path = self._write_results('pre_win2k', lines)
            return

        members = grp[0]['member'].values if hasattr(grp[0]['member'], 'values') else []
        members_str = [str(m) for m in members]

        everyone = any('S-1-1-0' in m or 'everyone' in m.lower() for m in members_str)
        anon     = any('S-1-5-7' in m or 'anonymous' in m.lower() for m in members_str)
        auth     = any('S-1-5-11' in m or 'authenticated users' in m.lower() for m in members_str)

        if everyone or anon:
            who = []
            if everyone: who.append('Everyone (S-1-1-0)')
            if anon:     who.append('Anonymous Logon (S-1-5-7)')
            print_error(f'  [CRITICAL] Pre-Windows 2000 group contains: {", ".join(who)}')
            print_error('  Any unauthenticated attacker can enumerate users, groups, and password policies.')
            lines.append(f'[CRITICAL] Group contains unauthenticated principals: {", ".join(who)}')
            lines.append('Remediation: net localgroup "Pre-Windows 2000 Compatible Access" Everyone /delete')
            lines.append('             net localgroup "Pre-Windows 2000 Compatible Access" "Anonymous Logon" /delete')
        elif auth:
            print_info('  [MEDIUM] Pre-Windows 2000 group contains Authenticated Users.')
            lines.append('[MEDIUM] Group contains Authenticated Users — broadens SAMR enumeration rights.')
            lines.append('Remediation: Remove Authenticated Users unless required by a legacy application.')
        elif members:
            print_info(f'  [LOW] Pre-Windows 2000 group has {len(members)} non-standard member(s):')
            lines.append(f'[LOW] {len(members)} non-standard member(s):')
            for m in members_str[:20]:
                print(f'  {m}')
                lines.append(f'  {m}')
        else:
            print_success('  [+] Pre-Windows 2000 Compatible Access group is empty — good.')
            lines.append('[OK] Group is empty.')

        path = self._write_results('pre_win2k', lines)


    # ==================================================================
    # ADCS / PKI HELPERS
    # ==================================================================

    def _get_config_dn(self) -> str:
        """Return the Configuration naming context DN."""
        return self.conn.server.info.other.get('configurationNamingContext', [''])[0]

    def _adcs_attr_int(self, entry, attr: str) -> int:
        """Safely read an integer attribute from an ldap3 entry."""
        try:
            v = entry[attr].value
            return int(v) if v is not None else 0
        except Exception:
            return 0

    def _adcs_attr_list(self, entry, attr: str) -> list:
        """Safely read a multi-valued attribute from an ldap3 entry."""
        try:
            vals = entry[attr].values
            return [str(v) for v in vals] if vals else []
        except Exception:
            return []

    def _get_template_enrollees(self, tmpl_dn: str, domain_sid: str) -> list:
        """
        Return a list of non-privileged principal names that have Enroll,
        AutoEnroll, or GenericAll rights on a certificate template.
        """
        enrollees = []
        try:
            ctrl = security_descriptor_control(sdflags=0x04)
            self.conn.search(
                search_base=tmpl_dn,
                search_filter='(objectClass=*)',
                search_scope=BASE,
                attributes=['nTSecurityDescriptor'],
                controls=ctrl,
            )
            if not self.conn.entries:
                return enrollees
            raw_sd = self.conn.entries[0]['nTSecurityDescriptor'].raw_values
            if not raw_sd or not raw_sd[0]:
                return enrollees
            seen = set()
            for ace in self._parse_sd_raw(raw_sd[0]):
                if ace['ace_type'] not in (0x00, 0x05):
                    continue
                sid  = ace['trustee_sid']
                otype = (ace.get('object_type') or '').lower().strip()
                mask = ace['access_mask']
                # Object ACE: only keep Enroll / AutoEnroll GUIDs
                if ace['ace_type'] == 0x05 and otype not in (_GUID_ENROLL, _GUID_AUTOENROLL):
                    continue
                # Access-allowed: only keep GenericAll
                if ace['ace_type'] == 0x00 and not (mask & _ACE_GENERIC_ALL):
                    continue
                if self._sid_is_privileged(sid, domain_sid):
                    continue
                if sid in seen:
                    continue
                seen.add(sid)
                enrollees.append(self._resolve_sid_to_name(sid))
        except Exception:
            pass
        return enrollees

    def _fmt_tmpl(self, name: str, enrollees: list) -> str:
        if enrollees:
            return f"{name} (enrollees: {', '.join(enrollees)})"
        return name

    def _load_adcs_templates(self):
        """
        Fetch all certificate templates once and cache them on the instance.
        Returns (templates_list, config_dn) or ([], '') if ADCS is absent.
        """
        if hasattr(self, '_cached_templates'):
            return self._cached_templates, self._cached_config_dn

        config_dn = self._get_config_dn()
        if not config_dn:
            self._cached_templates = []
            self._cached_config_dn = ''
            return [], ''

        tmpl_base = f'CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}'
        self.conn.search(
            tmpl_base,
            '(objectClass=pKICertificateTemplate)',
            search_scope=SUBTREE,
            attributes=[
                'cn', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
                'msPKI-RA-Signature', 'pKIExtendedKeyUsage', 'msPKI-Minimal-Key-Size',
                'msPKI-Template-Schema-Version', 'distinguishedName',
                'msPKI-Cert-Template-OID', 'nTSecurityDescriptor',
            ],
        )
        self._cached_templates = list(self.conn.entries)
        self._cached_config_dn = config_dn
        return self._cached_templates, config_dn

    def _load_adcs_cas(self):
        """Fetch Enrollment Service (CA) objects once and cache them."""
        if hasattr(self, '_cached_cas'):
            return self._cached_cas

        config_dn = self._get_config_dn()
        if not config_dn:
            self._cached_cas = []
            return []

        enroll_base = f'CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}'
        self.conn.search(
            enroll_base,
            '(objectClass=pKIEnrollmentService)',
            search_scope=SUBTREE,
            attributes=['cn', 'dNSHostName', 'certificateTemplates', 'distinguishedName'],
        )
        self._cached_cas = list(self.conn.entries)
        return self._cached_cas

    # ==================================================================
    # ADCS ESC1 — Enrollee-Supplied SAN + Client Auth
    # ==================================================================
    def check_adcs_esc1(self):
        print('\n' + '-' * 22 + 'ADCS ESC1 — Enrollee-Supplied SAN + Client Auth' + '-' * 10 + '\n')
        templates, config_dn = self._load_adcs_templates()
        domain_sid = self._get_domain_sid()
        lines = [f'ADCS ESC1 — Enrollee-Supplied SAN + Client Auth — {self.domain}']
        hits = []

        for t in templates:
            name = str(t['cn'].value)
            if name in _CA_TYPE_TEMPLATES:
                continue
            nf      = self._adcs_attr_int(t, 'msPKI-Certificate-Name-Flag')
            ef      = self._adcs_attr_int(t, 'msPKI-Enrollment-Flag')
            ra_sigs = self._adcs_attr_int(t, 'msPKI-RA-Signature')
            ekus    = set(self._adcs_attr_list(t, 'pKIExtendedKeyUsage'))
            approval = bool(ef & _CT_PEND_ALL_REQUESTS)

            if ((nf & _CT_ENROLLEE_SUPPLIES_SUBJECT)
                    and (ekus & _CLIENT_AUTH_EKUS or _ANY_PURPOSE_EKU in ekus or len(ekus) == 0)
                    and not approval
                    and ra_sigs == 0):
                dn = str(t['distinguishedName'].value or '')
                enrollees = self._get_template_enrollees(dn, domain_sid) if dn else []
                hits.append(self._fmt_tmpl(name, enrollees))

        if hits:
            print_error(f'  [CRITICAL] {len(hits)} template(s) allow privilege escalation via SAN manipulation:')
            lines.append(f'[CRITICAL] {len(hits)} template(s) — enrollee can supply arbitrary SAN + client auth, no approval:')
            for h in hits:
                print(Fore.RED + f'  {h}' + Style.RESET_ALL)
                lines.append(f'  {h}')
            lines.append('')
            lines.append("Remediation: Disable 'Supply in the request' on the template or enable manager approval.")
        else:
            print_success('  [+] No ESC1-vulnerable templates found.')
            lines.append('[OK] No enrollee-supplied SAN + client auth templates without approval.')

        path = self._write_results('adcs_esc1', lines)


    # ==================================================================
    # ADCS ESC2 — Any Purpose / No EKU Templates
    # ==================================================================
    def check_adcs_esc2(self):
        print('\n' + '-' * 22 + 'ADCS ESC2 — Any Purpose / No EKU Templates' + '-' * 15 + '\n')
        templates, config_dn = self._load_adcs_templates()
        domain_sid = self._get_domain_sid()
        lines = [f'ADCS ESC2 — Any Purpose / No EKU Templates — {self.domain}']
        hits = []

        for t in templates:
            name = str(t['cn'].value)
            if name in _CA_TYPE_TEMPLATES:
                continue
            ef   = self._adcs_attr_int(t, 'msPKI-Enrollment-Flag')
            ekus = set(self._adcs_attr_list(t, 'pKIExtendedKeyUsage'))

            if (_ANY_PURPOSE_EKU in ekus or len(ekus) == 0) and not (ef & _CT_PEND_ALL_REQUESTS):
                dn = str(t['distinguishedName'].value or '')
                enrollees = self._get_template_enrollees(dn, domain_sid) if dn else []
                hits.append(self._fmt_tmpl(name, enrollees))

        if hits:
            print_error(f'  [CRITICAL] {len(hits)} template(s) with overly broad EKU (Any Purpose / none):')
            lines.append(f'[CRITICAL] {len(hits)} template(s) with Any Purpose or no EKU restriction:')
            for h in hits:
                print(Fore.RED + f'  {h}' + Style.RESET_ALL)
                lines.append(f'  {h}')
            lines.append('')
            lines.append('Remediation: Restrict EKU to specific required purposes only.')
        else:
            print_success('  [+] No ESC2-vulnerable templates found.')
            lines.append('[OK] No Any Purpose / empty EKU templates without approval.')

        path = self._write_results('adcs_esc2', lines)


    # ==================================================================
    # ADCS ESC3 — Enrollment Agent Templates
    # ==================================================================
    def check_adcs_esc3(self):
        print('\n' + '-' * 22 + 'ADCS ESC3 — Enrollment Agent Templates' + '-' * 20 + '\n')
        templates, config_dn = self._load_adcs_templates()
        domain_sid = self._get_domain_sid()
        lines = [f'ADCS ESC3 — Enrollment Agent Templates — {self.domain}']
        hits = []

        for t in templates:
            name = str(t['cn'].value)
            ef   = self._adcs_attr_int(t, 'msPKI-Enrollment-Flag')
            ekus = set(self._adcs_attr_list(t, 'pKIExtendedKeyUsage'))

            if _ENROLL_AGENT_EKU in ekus and not (ef & _CT_PEND_ALL_REQUESTS):
                dn = str(t['distinguishedName'].value or '')
                enrollees = self._get_template_enrollees(dn, domain_sid) if dn else []
                hits.append(self._fmt_tmpl(name, enrollees))

        if hits:
            print_error(f'  [HIGH] {len(hits)} enrollment agent template(s) without approval:')
            lines.append(f'[HIGH] {len(hits)} enrollment agent template(s) — allows requesting certs on behalf of others:')
            for h in hits:
                print(Fore.RED + f'  {h}' + Style.RESET_ALL)
                lines.append(f'  {h}')
            lines.append('')
            lines.append('Remediation: Enable manager approval on enrollment agent templates.')
        else:
            print_success('  [+] No ESC3-vulnerable enrollment agent templates found.')
            lines.append('[OK] No enrollment agent templates without approval.')

        path = self._write_results('adcs_esc3', lines)


    # ==================================================================
    # ADCS ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA
    # ==================================================================
    def check_adcs_esc6(self):
        print('\n' + '-' * 22 + 'ADCS ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2' + '-' * 15 + '\n')
        config_dn = self._get_config_dn()
        if not config_dn:
            print_error('  [!] Cannot determine configuration naming context.')
            return
        cas = self._load_adcs_cas()
        cert_auth_base = f'CN=Certification Authorities,CN=Public Key Services,CN=Services,{config_dn}'
        lines = [f'ADCS ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 — {self.domain}']
        hits = []

        for ca in cas:
            ca_name = str(ca['cn'].value)
            self.conn.search(
                cert_auth_base,
                f'(&(objectClass=certificationAuthority)(cn={ca_name}))',
                search_scope=SUBTREE,
                attributes=['flags'],
            )
            ca_configs = list(self.conn.entries)
            if ca_configs:
                flags = self._adcs_attr_int(ca_configs[0], 'flags')
                if flags & _CA_FLAG_EDITF_ATTRIBUTESUBJECTALTNAME2:
                    hits.append(ca_name)

        if hits:
            print_error(f'  [CRITICAL] {len(hits)} CA(s) allow arbitrary SAN on any request:')
            lines.append(f'[CRITICAL] {len(hits)} CA(s) with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled:')
            for h in hits:
                print(Fore.RED + f'  {h}' + Style.RESET_ALL)
                lines.append(f'  {h}')
            lines.append('')
            lines.append("Remediation: certutil -config '<CA>' -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2")
        else:
            print_success('  [+] No CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 found (ESC6 clean).')
            lines.append('[OK] No CAs have EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.')

        path = self._write_results('adcs_esc6', lines)


    # ==================================================================
    # ADCS ESC8 — HTTP Web Enrollment (certsrv) Accessible
    # ==================================================================
    def check_adcs_esc8(self):
        print('\n' + '-' * 22 + 'ADCS ESC8 — HTTP Web Enrollment (certsrv)' + '-' * 16 + '\n')
        cas = self._load_adcs_cas()
        lines = [f'ADCS ESC8 — HTTP Web Enrollment — {self.domain}']
        hits = []

        for ca in cas:
            host = str(ca['dNSHostName'].value or '')
            if not host:
                continue
            try:
                urllib.request.urlopen(f'http://{host}/certsrv/', timeout=3)
                hits.append(host)
            except Exception:
                pass

        if hits:
            print_error(f'  [CRITICAL] {len(hits)} CA(s) have HTTP web enrollment accessible — NTLM relay possible:')
            lines.append(f'[CRITICAL] {len(hits)} CA(s) with certsrv over HTTP:')
            for h in hits:
                print(Fore.RED + f'  {h}' + Style.RESET_ALL)
                lines.append(f'  {h}')
            lines.append('')
            lines.append('Remediation: Enable HTTPS + EPA on certsrv. Disable NTLM where possible.')
        else:
            print_success('  [+] No HTTP certsrv endpoints found (ESC8 clean).')
            lines.append('[OK] No accessible HTTP web enrollment endpoints.')

        path = self._write_results('adcs_esc8', lines)


    # ==================================================================
    # ADCS ESC9 — No Security Extension on Client Auth Templates
    # ==================================================================
    def check_adcs_esc9(self):
        print('\n' + '-' * 22 + 'ADCS ESC9 — No Security Extension' + '-' * 24 + '\n')
        templates, config_dn = self._load_adcs_templates()
        domain_sid = self._get_domain_sid()
        lines = [f'ADCS ESC9 — No Security Extension — {self.domain}']
        hits = []

        for t in templates:
            name = str(t['cn'].value)
            ef   = self._adcs_attr_int(t, 'msPKI-Enrollment-Flag')
            ekus = set(self._adcs_attr_list(t, 'pKIExtendedKeyUsage'))

            if (ef & _CT_NO_SECURITY_EXT) and (ekus & _CLIENT_AUTH_EKUS):
                dn = str(t['distinguishedName'].value or '')
                enrollees = self._get_template_enrollees(dn, domain_sid) if dn else []
                hits.append(self._fmt_tmpl(name, enrollees))

        if hits:
            print_error(f'  [HIGH] {len(hits)} client auth template(s) have CT_FLAG_NO_SECURITY_EXTENSION:')
            lines.append(f'[HIGH] {len(hits)} template(s) — no szOID_NTDS_CA_SECURITY_EXT in issued cert:')
            for h in hits:
                print(Fore.RED + f'  {h}' + Style.RESET_ALL)
                lines.append(f'  {h}')
            lines.append('')
            lines.append('Remediation: Remove CT_FLAG_NO_SECURITY_EXTENSION from all client auth templates.')
        else:
            print_success('  [+] No ESC9-vulnerable templates found.')
            lines.append('[OK] No client auth templates with CT_FLAG_NO_SECURITY_EXTENSION.')

        path = self._write_results('adcs_esc9', lines)


    # ==================================================================
    # ADCS ESC10 — Weak Certificate Mapping Enforcement
    # ==================================================================
    def check_adcs_esc10(self):
        print('\n' + '-' * 22 + 'ADCS ESC10 — Certificate Mapping Enforcement' + '-' * 13 + '\n')
        templates, config_dn = self._load_adcs_templates()
        lines = [f'ADCS ESC10 — Certificate Mapping Enforcement — {self.domain}']

        client_auth_tmpls = []
        for t in templates:
            ekus = set(self._adcs_attr_list(t, 'pKIExtendedKeyUsage'))
            if ekus & _CLIENT_AUTH_EKUS:
                client_auth_tmpls.append(str(t['cn'].value))

        if client_auth_tmpls:
            print_info(f'  [MEDIUM] {len(client_auth_tmpls)} client authentication template(s) exist.')
            print_info('  If StrongCertificateBindingEnforcement = 0 on DCs, UPN spoofing is possible.')
            lines.append(f'[MEDIUM] {len(client_auth_tmpls)} client auth template(s) — check DC registry:')
            for name in client_auth_tmpls[:30]:
                lines.append(f'  {name}')
            lines.append('')
            lines.append('Remediation: Set HKLM\\System\\CurrentControlSet\\Services\\Kdc\\'
                         'StrongCertificateBindingEnforcement = 2 on all DCs.')
        else:
            print_success('  [+] No client authentication templates found.')
            lines.append('[OK] No client auth templates present.')

        path = self._write_results('adcs_esc10', lines)


    # ==================================================================
    # ADCS ESC11 — CA Accepts Non-Encrypted RPC Requests
    # ==================================================================
    def check_adcs_esc11(self):
        print('\n' + '-' * 22 + 'ADCS ESC11 — Non-Encrypted RPC' + '-' * 27 + '\n')
        config_dn = self._get_config_dn()
        if not config_dn:
            print_error('  [!] Cannot determine configuration naming context.')
            return
        cas = self._load_adcs_cas()
        cert_auth_base = f'CN=Certification Authorities,CN=Public Key Services,CN=Services,{config_dn}'
        lines = [f'ADCS ESC11 — Non-Encrypted RPC — {self.domain}']
        hits = []

        for ca in cas:
            ca_name = str(ca['cn'].value)
            self.conn.search(
                cert_auth_base,
                f'(&(objectClass=certificationAuthority)(cn={ca_name}))',
                search_scope=SUBTREE,
                attributes=['flags'],
            )
            ca_configs = list(self.conn.entries)
            if ca_configs:
                flags = self._adcs_attr_int(ca_configs[0], 'flags')
                if flags & _CA_FLAG_IF_ENFORCEENCRYPTICERTREQUEST:
                    hits.append(ca_name)

        if hits:
            print_error(f'  [HIGH] {len(hits)} CA(s) accept non-encrypted RPC — NTLM relay over RPC possible:')
            lines.append(f'[HIGH] {len(hits)} CA(s) without encrypted RPC enforcement:')
            for h in hits:
                print(Fore.RED + f'  {h}' + Style.RESET_ALL)
                lines.append(f'  {h}')
            lines.append('')
            lines.append('Remediation: Enable SSL/TLS on the CA RPC interface.')
        else:
            print_success('  [+] No CAs accepting non-encrypted RPC (ESC11 clean).')
            lines.append('[OK] All CAs enforce encrypted RPC.')

        path = self._write_results('adcs_esc11', lines)


    # ==================================================================
    # ADCS ESC13 — Issuance Policy Linked to AD Group
    # ==================================================================
    def check_adcs_esc13(self):
        print('\n' + '-' * 22 + 'ADCS ESC13 — Issuance Policy Linked to AD Group' + '-' * 10 + '\n')
        templates, config_dn = self._load_adcs_templates()
        if not config_dn:
            print_error('  [!] Cannot determine configuration naming context.')
            return
        domain_sid = self._get_domain_sid()
        pki_base = f'CN=Public Key Services,CN=Services,{config_dn}'
        lines = [f'ADCS ESC13 — Issuance Policy Linked to AD Group — {self.domain}']
        hits = []

        for t in templates:
            name    = str(t['cn'].value)
            ef      = self._adcs_attr_int(t, 'msPKI-Enrollment-Flag')
            ra_sigs = self._adcs_attr_int(t, 'msPKI-RA-Signature')
            oid     = str(t['msPKI-Cert-Template-OID'].value or '')

            if not oid or (ef & _CT_PEND_ALL_REQUESTS) or ra_sigs != 0:
                continue

            # Check if any OID policy object links this template OID to a group
            self.conn.search(
                pki_base,
                f'(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*)(msPKI-Cert-Template-OID={oid}))',
                search_scope=SUBTREE,
                attributes=['cn', 'msDS-OIDToGroupLink'],
            )
            for pol in self.conn.entries:
                group_dn = str(pol['msDS-OIDToGroupLink'].value or '')
                if group_dn:
                    dn = str(t['distinguishedName'].value or '')
                    enrollees = self._get_template_enrollees(dn, domain_sid) if dn else []
                    hits.append(self._fmt_tmpl(name, enrollees) + f' -> linked group: {group_dn}')

        if hits:
            print_error(f'  [HIGH] {len(hits)} template(s) grant group membership via certificate enrollment:')
            lines.append(f'[HIGH] {len(hits)} template(s) with issuance policy linked to AD group:')
            for h in hits:
                print(Fore.RED + f'  {h}' + Style.RESET_ALL)
                lines.append(f'  {h}')
            lines.append('')
            lines.append('Remediation: Audit msDS-OIDToGroupLink on all issuance policy OIDs.')
        else:
            print_success('  [+] No ESC13-vulnerable templates found.')
            lines.append('[OK] No issuance policies linked to AD groups.')

        path = self._write_results('adcs_esc13', lines)


    # ==================================================================
    # ADCS ESC15 — Schema v1 Template with Enrollee-Supplied SAN
    # ==================================================================
    def check_adcs_esc15(self):
        print('\n' + '-' * 22 + 'ADCS ESC15 — Schema v1 + Enrollee SAN' + '-' * 20 + '\n')
        templates, config_dn = self._load_adcs_templates()
        domain_sid = self._get_domain_sid()
        lines = [f'ADCS ESC15 — Schema v1 + Enrollee SAN — {self.domain}']
        hits = []

        for t in templates:
            name       = str(t['cn'].value)
            schema_ver = self._adcs_attr_int(t, 'msPKI-Template-Schema-Version')
            ef         = self._adcs_attr_int(t, 'msPKI-Enrollment-Flag')
            nf         = self._adcs_attr_int(t, 'msPKI-Certificate-Name-Flag')
            ekus       = set(self._adcs_attr_list(t, 'pKIExtendedKeyUsage'))

            if (schema_ver == 1
                    and (nf & _CT_ENROLLEE_SUPPLIES_SUBJECT)
                    and not (ef & _CT_PEND_ALL_REQUESTS)
                    and (ekus & _CLIENT_AUTH_EKUS)):
                dn = str(t['distinguishedName'].value or '')
                enrollees = self._get_template_enrollees(dn, domain_sid) if dn else []
                hits.append(self._fmt_tmpl(name, enrollees))

        if hits:
            print_error(f'  [CRITICAL] {len(hits)} schema v1 template(s) allow SAN supply + client auth:')
            lines.append(f'[CRITICAL] {len(hits)} schema v1 template(s) — enrollee-supplied SAN + client auth:')
            for h in hits:
                print(Fore.RED + f'  {h}' + Style.RESET_ALL)
                lines.append(f'  {h}')
            lines.append('')
            lines.append('Remediation: Upgrade template schema version or disable enrollee-supplied SAN.')
        else:
            print_success('  [+] No ESC15-vulnerable templates found.')
            lines.append('[OK] No schema v1 templates with enrollee SAN + client auth.')

        path = self._write_results('adcs_esc15', lines)


    # ==================================================================
    # ADCS Weak Key Size
    # ==================================================================
    def check_adcs_weak_key(self):
        print('\n' + '-' * 22 + 'ADCS Weak Key Size in Certificate Templates' + '-' * 14 + '\n')
        templates, config_dn = self._load_adcs_templates()
        lines = [f'ADCS Weak Key Size — {self.domain}']
        hits = []

        for t in templates:
            name     = str(t['cn'].value)
            key_size = self._adcs_attr_int(t, 'msPKI-Minimal-Key-Size')
            if key_size and key_size < 2048:
                hits.append(f'{name} ({key_size}-bit)')

        if hits:
            print_error(f'  [MEDIUM] {len(hits)} template(s) use key sizes below 2048-bit:')
            lines.append(f'[MEDIUM] {len(hits)} template(s) with weak key sizes:')
            for h in hits:
                print(Fore.YELLOW + f'  {h}' + Style.RESET_ALL)
                lines.append(f'  {h}')
            lines.append('')
            lines.append('Remediation: Require minimum 2048-bit RSA or 256-bit ECC keys.')
        else:
            print_success('  [+] All certificate templates use key sizes >= 2048-bit.')
            lines.append('[OK] No weak key sizes detected.')

        path = self._write_results('adcs_weak_key', lines)


    def _finish(self):
        """Print timing summary and cleanly unbind."""
        self.t2 = datetime.now()
        elapsed = self.t2 - self.t1
        # Trim microseconds for readability
        elapsed_str = str(elapsed).split('.')[0]
        print('\n' + '='*80)
        print_success(f'[+] Enumeration complete. Text files containing raw data have been placed in the output directory for your review.')
        print_info(f'    Started   : {self.run_ts}')
        print_info(f'    Finished  : {self.t2.strftime("%Y-%m-%d %H:%M")}')
        print_info(f'    Elapsed   : {elapsed_str}')
        if self.dir_name:
            try:
                files = sorted(
                    f for f in os.listdir(self.dir_name)
                    if os.path.isfile(os.path.join(self.dir_name, f))
                )
                print_info(f'    Output dir: {self.dir_name}  ({len(files)} file(s))')
                for fname in files:
                    fpath = os.path.join(self.dir_name, fname)
                    kb = os.path.getsize(fpath) / 1024
                    print_info(f'      {fname:<50} {kb:>6.1f} KB')
            except Exception:
                pass
        print('=' * 80 + '\n')
        self._close_log()
        self.conn.unbind()

    def _close_log(self):
        """Restore original stdout/stderr and close the log file."""
        if self._log_fh:
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
            self._log_fh.close()
            self._log_fh = None

    def run(self):
        init()
        self.banner()
        self.arg_handler()
        try:
            if self.subnet:
                self.portscan()
            if self.args.anon:
                self.anonymous_bind()
            elif self.args.ntlm:
                self.password = f"aad3b435b51404eeaad3b435b51404ee:{self.args.ntlm}"
                print_info(f"Using NTLM hash: {self.password}")
                self.ntlm_bind()
            elif self.args.password:
                self.authenticated_bind()
        except ValueError as ve:
            print_error(str(ve))
            sys.exit(1)
        except KeyboardInterrupt:
            print_info('\n[info] Interrupted by user. Exiting...')


if __name__ == "__main__":
    ldap_search = LDAPSearch()
    ldap_search.run()
