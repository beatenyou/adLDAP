# adLDAP - Active Directory LDAP Enumerator

adLDAP is an Active Directory LDAP enumeration tool implemented in Python3. It provides comprehensive domain reconnaissance, user and group enumeration, delegation analysis, DACL inspection, and a full suite of vulnerability and security checks including ADCS certificate template abuse (ESC1-ESC15).

The tool wraps the `ldap3` library for LDAP communication and `impacket` for binary security descriptor parsing. It is optimized for use on Windows but is functional on Linux with some features limited (e.g., hostname-to-IP resolution).

## Installation

```
pip3 install -r requirements.txt
```

## Authentication Modes

### Anonymous Bind

Anonymous binding attempts unauthenticated access against the domain controller. This mode extracts basic domain information including naming contexts, DNS hostnames, and domain functionality levels.

```
python3 adLDAP.py -a --dc <DC_IP>
```

### Authenticated Bind (LDAPS)

Credentialed binding over LDAPS (port 636) performs full domain enumeration including users, groups, computers, delegation, GPOs, and more. All output is saved to text files in a timestamped directory.

```
python3 adLDAP.py --dc <DC_IP> --user <username> --password <password>
```

### NTLM Bind

Pass-the-hash authentication using an NTLM hash instead of a plaintext password.

```
python3 adLDAP.py --dc <DC_IP> --user <username> --ntlm <hash>
```

### Force Port 389

Force an unencrypted LDAP connection on port 389 instead of LDAPS.

```
python3 adLDAP.py --dc <DC_IP> --user <username> --password <password> --no-ssl
```

## Domain Enumeration

When run without targeted flags, adLDAP performs a full domain enumeration including:

- Current user information and group memberships
- Password policy and machine account quota
- Group Managed Service Accounts (gMSA) with password hashes
- LAPS passwords (if readable)
- All domain users and users with non-expiring passwords
- Domain groups
- Admin-level users (admin and operator groups)
- Kerberoastable accounts
- AS-REP roastable accounts
- Unconstrained and constrained delegations
- All domain computers with hostname resolution (Windows)
- Domain controllers
- Domain trusts and trust direction
- Servers and deprecated operating systems
- MSSQL and Exchange servers
- Group Policy Objects
- Protected admin users (adminCount=1)
- User descriptions containing interesting fields (passwords, keys, etc.)

All results are written to individual text files in a timestamped output directory. A full console log is also captured automatically.

## Targeted Mode

When any specific flag is provided, adLDAP runs in **targeted mode** -- only the requested checks execute, skipping the full enumeration. This allows fast, focused queries.

```
# Only RBCD enumeration
python3 adLDAP.py --dc <DC_IP> --user <username> --password <password> --rbcd

# Only DACL analysis for a specific object
python3 adLDAP.py --dc <DC_IP> --user <username> --password <password> --dacl K2ROOTDC$

# Combine multiple targeted checks
python3 adLDAP.py --dc <DC_IP> --user <username> --password <password> --rbcd --dcsync --adcs-esc1
```

### Additional Enumeration Flags

| Flag | Description |
|------|-------------|
| `--group-members` | Enumerate all group memberships with member resolution |
| `--rbcd` | Enumerate Resource Based Constrained Delegation configurations |
| `--dacl` | Enumerate dangerous DACL ACEs for all users, computers, and groups |
| `--dacl <name>` | Target a specific object by sAMAccountName |
| `--dacl-type <type>` | Restrict DACL scope to `user`, `computer`, or `group` |

## Vulnerability & Security Checks

Run all checks at once with `--vuln-scan`, or select individual checks:

| Flag | Description |
|------|-------------|
| `--vuln-scan` | Run ALL vulnerability checks in one pass |
| `--adminsdholder` | Inspect AdminSDHolder ACL for unexpected write permissions |
| `--sid-history` | Detect accounts carrying privileged SIDs in sIDHistory |
| `--shadow-creds` | Enumerate msDS-KeyCredentialLink entries (Shadow Credentials) |
| `--foreign-principals` | Find Foreign Security Principals in privileged groups |
| `--dangerous-delegation` | Find constrained delegation on sensitive DC services |
| `--rbcd-domain` | Check RBCD on the domain object and DC computer objects |
| `--indirect-admins` | Find transitive (nested) members of privileged groups |
| `--dcsync` | Find non-privileged principals with DCSync replication rights |
| `--protected-users` | Report Protected Users group membership and flag gaps |
| `--rc4` | Find service accounts and DCs permitting RC4 Kerberos encryption |
| `--pre-win2k` | Check Pre-Windows 2000 Compatible Access group membership |

### ADCS / PKI Checks

| Flag | Description |
|------|-------------|
| `--adcs-esc1` | Templates with enrollee-supplied SAN + client auth |
| `--adcs-esc2` | Templates with Any Purpose or no EKU |
| `--adcs-esc3` | Enrollment agent templates without approval |
| `--adcs-esc4` | Non-privileged write ACEs on certificate templates |
| `--adcs-esc5` | Non-privileged write ACEs on PKI container objects |
| `--adcs-esc6` | CA with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled |
| `--adcs-esc7` | Non-privileged CA Officer/Manager rights |
| `--adcs-esc8` | HTTP web enrollment (certsrv) accessibility |
| `--adcs-esc9` | Templates with CT_FLAG_NO_SECURITY_EXTENSION + client auth |
| `--adcs-esc10` | Client auth templates vulnerable to weak cert mapping |
| `--adcs-esc11` | CA accepting non-encrypted RPC requests |
| `--adcs-esc13` | Templates with issuance policy linked to AD group |
| `--adcs-esc15` | Schema v1 templates with enrollee-supplied SAN + client auth |
| `--adcs-weak-key` | Certificate templates with key size below 2048-bit |

## Output

All output is written to a timestamped directory (e.g., `domain.local_2026-03-04_1430/`). The directory contains:

- Individual `.txt` files for each enumeration category
- A `.console.log` file capturing all terminal output (with ANSI colors stripped)
- A summary at the end of execution listing all generated files and sizes

## Disclaimer

This tool is designed for authorized penetration testing and security assessments only. Usage of adLDAP for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. The developer assumes no liability and is not responsible for any misuse or damage caused by this tool.

## Credits

- gMSA password dumping based on [gMSADumper](https://github.com/micahvandeusen/gMSADumper)
- ADCS vulnerability checks inspired by [ADPulse](https://github.com/dievus/ADPulse)
- Original project by [TheMayor](https://github.com/dievus)
