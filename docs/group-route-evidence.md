# Group route evidence

A room is the authorization principal: once DEVin is in an allowlisted group,
**any member** may use him after addressing him. This is the transcript that
proves it on the live VPS, with the real encrypted credentials.

## 1. The live check

`devin/scripts/live_group_check.py`, run under the service's own credentials
(`systemd-run --property=LoadCredentialEncrypted=…`). It drives the deployed
`DevinBot` object and **captures** group replies instead of sending them, so
proving the route cannot spam the room.

```
allowlists the deployed service really loaded:
  users : [7898354400]
  groups: [-1004351143165, -1003533071599]
  github credential present: False
  sealing key present      : False
  bot identity pin         : id=8803435794 @DEVinlooperbot

ok  bare /help            (never delivered under group privacy) ignored  (not addressed in group)
ok  /help@DEVinlooperbot                           replied  (help)  -> POST chat_id=-1004351143165 reply_to=102
ok  @DEVinlooperbot /help   (mention prefix)       replied  (help)  -> POST chat_id=-1004351143165 reply_to=103
ok  @DEVinlooperbot what do you do?   (bare mention) replied  (hint)  -> POST chat_id=-1004351143165 reply_to=104
ok  reply to one of his messages                   replied  (help)  -> POST chat_id=-1004351143165 reply_to=105
ok  sibling bot, bare mention  (loop breaker)      ignored  (not addressed in group)
ok  sibling bot, addressed command                 replied  (help)  -> POST chat_id=-1004351143165 reply_to=107

real DM round trip: replied (help)  <- check your DM
exit=0
```

The sender in those cases is `424242` — a room member who is **not** on the DM
user allowlist, which is exactly the case that used to be denied. `github
credential present: False` / `sealing key present: False` appear because this
check mounts only the Telegram credential; the service itself mounts all three.

## 2. Production, from the service's own journal

```
DEVin online: @DEVinlooperbot id=8803435794 dm_allow=1
  groups=[-1004351143165, -1003533071599] sealing=yes github=yes
  can_read_all_group_messages=False

update=886428504 chat=-1004351143165 type=supergroup from=7898354400
  bot=False thread=None kind=/crawl@DEVinlooperbot
  -> replied (crawl:https://d0xeddev.com)

update=886428505 chat=-1003533071599 type=supergroup from=731848123
  bot=False thread=None kind=<non-text>
  -> ignored (not addressed in group)
```

Read those two lines together: a real addressed group command was answered in
`@looper_collective`, and a real message from a different member in the other
group was correctly ignored because it was not addressed. Both were handled by
the same long-running process (`NRestarts=0`).

Journal lines carry no message text and no credential values.

## 3. What the privacy flag means

`can_read_all_group_messages=False` is Telegram's outer filter: only messages
that mention the bot, address a `/command@self` to it, or reply to it are ever
delivered. A bare `/crawl` in a room is therefore never received, and no amount
of loosening inside the bot can answer it. The supported forms are the ones the
table in [`ARCHITECT.md`](ARCHITECT.md#4-authorization-and-addressing) lists.

## 4. Reproducing

```sh
printf "%s\n" "DEVIN_ALLOWED_USERS=<owner-id>" \
  "DEVIN_ALLOWED_GROUPS=\"-1004351143165 -1003533071599\"" \
  "DEVIN_BOT_ID=8803435794" "DEVIN_BOT_USERNAME=DEVinlooperbot" > /tmp/devin-env

systemd-run --pipe --wait --collect \
  --setenv=PYTHONPATH=/srv/looper-agents/devin/app \
  --property=EnvironmentFile=/tmp/devin-env \
  --property=LoadCredentialEncrypted=telegram_token:/etc/credstore.encrypted/looper-devin.token \
  /srv/looper-agents/devin/venv/bin/python \
  /srv/looper-agents/devin/app/devin/scripts/live_group_check.py
```

Verify the allowlist that **systemd actually applied** — never the unit file,
which can read perfectly while systemd dropped a value:

```sh
systemctl show looper-devin -p Environment
```

An `Environment=` line with several space-separated values must be quoted:
unquoted, systemd applies the first token and logs `Invalid environment
assignment, ignoring: <rest>`, which silently removed a whole group here.
