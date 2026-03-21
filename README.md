<p align="center">
  <img src="https://github.com/beatenyou/adLDAP/tree/main/adLDAP.png" alt="adLDAP">
</p>
# adLDAP - Active Directory LDAP Enumerator

adLDAP is an Active Directory LDAP enumeration tool implemented in Python3. It provides comprehensive domain reconnaissance, user and group enumeration, delegation analysis, DACL inspection, and a full suite of vulnerability and security checks including ADCS certificate template abuse (ESC1-ESC15).

The tool wraps the `ldap3` library for LDAP communication and `impacket` for binary security descriptor parsing. It is cross-platform -- optimized for Windows with full functionality on Linux (hostname-to-IP resolution is Windows-only).

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

Force an unencrypted LDAP connection on port 389 instead of LDAPS. Useful when the DC does not have LDAPS configured.

```
python3 adLDAP.py --dc <DC_IP> --user <username> --password <password> --no-ssl
```

## Domain Enumeration

When run without targeted flags, adLDAP performs a full domain enumeration including:

- **Current user information** -- UAC flag decoding, adminCount status, and transitive privileged group membership via LDAP (cross-platform, no `whoami` dependency)
- **Password policy** -- complexity requirements, lockout thresholds, fine-grained password policies, and machine account quota
- **Group Managed Service Accounts (gMSA)** -- account enumeration with full password hash extraction (NTLM, AES256, AES128) and readable-by principals
- **LAPS passwords** (if readable by the authenticated user)
- **All domain users** and **users with non-expiring passwords**
- **Stale accounts** -- disabled accounts, locked-out accounts, and accounts that have never logged on
- **Domain groups with member listing** -- each group displays its member count and member names (CN extracted from DN)
- **Admin-level users** -- members of admin and operator groups (console output capped at 25 per group, full list in file)
- **Kerberoastable accounts** -- users with SPNs that are not disabled
- **AS-REP roastable accounts** -- users with Kerberos pre-authentication disabled
- **Unconstrained and constrained delegations** -- accounts trusted for delegation and their allowed targets
- **All domain computers** with hostname resolution (Windows)
- **Domain controllers**
- **Domain trusts** with trust direction and trust type
- **Servers and deprecated operating systems** -- Windows 2003, XP, Vista, 7, 8, 2008
- **MSSQL and Exchange servers**
- **Group Policy Objects**
- **Protected admin users** (adminCount=1)
- **User descriptions** containing interesting fields (passwords, keys, tokens, etc.)

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
| `--group-members` | Enumerate all group memberships with member resolution and object type tagging (User, Group, Computer, gMSA) |
| `--rbcd` | Enumerate Resource Based Constrained Delegation configurations with ACL member resolution |
| `--dacl` | Enumerate dangerous DACL ACEs for all users, computers, and groups |
| `--dacl <name>` | Target a specific object by sAMAccountName |
| `--dacl-type <type>` | Restrict DACL scope to `user`, `computer`, or `group` |

### DACL Rights Detected

The DACL check identifies the following dangerous permissions on Active Directory objects:

- **GenericAll** -- full control over the object
- **GenericWrite** -- write any attribute on the object
- **WriteOwner** -- change the object owner
- **WriteDACL** -- modify the object DACL
- **WriteProperty(All)** -- write all properties
- **ForceChangePassword** -- reset the target user password without knowing the current one
- **AddMember / AddSelf** -- add members to a group
- **WriteSPN** -- modify the servicePrincipalName attribute (Kerberoasting path)
- **WriteRBCD** -- write the msDS-AllowedToActOnBehalfOfOtherIdentity attribute (RBCD abuse path)

Default and privileged trustees (Domain Admins, Enterprise Admins, SYSTEM, etc.) are filtered out to reduce noise.

## Vulnerability & Security Checks

Run all checks at once with `--vuln-scan`, or select individual checks:

| Flag | Description |
|------|-------------|
| `--vuln-scan` | Run ALL vulnerability checks in one pass |
| `--adminsdholder` | Inspect AdminSDHolder ACL for unexpected write permissions (SDProp persistence) |
| `--sid-history` | Detect accounts carrying privileged SIDs in sIDHistory |
| `--shadow-creds` | Enumerate msDS-KeyCredentialLink entries (Shadow Credentials) |
| `--foreign-principals` | Find Foreign Security Principals in privileged groups |
| `--dangerous-delegation` | Find constrained delegation on sensitive DC services (ldap, cifs, host, gc) |
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

Each output file includes a header with the domain name and run timestamp for easy identification.

## Disclaimer

This tool is designed for authorized security assessments only. Usage of adLDAP for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. The developer assumes no liability and is not responsible for any misuse or damage caused by this tool.

## Credits

- gMSA password dumping based on [gMSADumper](https://github.com/micahvandeusen/gMSADumper)
- ADCS vulnerability checks inspired by [ADPulse](https://github.com/dievus/ADPulse)
- Original project by [TheMayor](https://github.com/dievus)
