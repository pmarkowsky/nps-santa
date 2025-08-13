# Common Expression Language (CEL)

This page lists well-known and/or community-contributed CEL expressions.

## Apps signed since X

This will prevent executions of an app where the specific binary was signed
before the provided date. This is particularly useful when attached to a
`TEAMID` or `SIGNINGID` rule.

```clike
target.signing_time >= timestamp('2025-05-31T00:00:00Z')
```

## Prevent users from disabling gatekeeper

Create a signing ID rule for `platform:com.apple.spctl` and attach the following CEL program

```clike
['--global-disable', '--master-disable','--disable', '--add', '--remove'].exists(flag, flag in args) ? BLOCKLIST : ALLOWLIST
```

## Prevent users from enabling remote access via SSH on the command line

**Requires:** Santa 2025.8+

As seen on [Loobins lateral movement section](https://www.loobins.io/binaries/systemsetup/#enable-remote-login)

Users can use `systemsetup` to enable remote access via SSH on the command line.

This can be prevented by creating a signing ID rule for `platform:com.apple.systemsetup` with the following CEL policy

```clike
args.join(' ').contains("-setremotelogin on")
```

## Prevent Users from enabling remote apple events

**Requires:** Santa 2025.8+

As seen on [Loobins lateral movement section](https://www.loobins.io/binaries/systemsetup/#enable-remote-apple-events)

Users can use `systemsetup` to enable Remote Apple Events from other
computers. 

This can be prevented by creating a signing ID rule for
`platform:com.apple.systemsetup` with the following CEL policy

```clike
args.join(' ').contains("-setremoteappleevents on")
```
