# Safe family passwords

A Safe created by an agent inherits its mother's password through a family
credential. Every member still has a separate encrypted volume and data key.
Changing that password updates the current local family's password wrappers;
it does not rewrite files or replace those data keys.

Unlock writable Oblivion storage and close every Safe in the affected family.
Unrelated Safes can stay open. Preview the exact local members before changing:

```sh
oblivion safe password preview GB --json
oblivion safe password GB
```

The CLI lists the affected Safes, requests `CHANGE`, then reads the current and
new passwords privately. Passwords never enter process arguments. The manager
uses the preview's digest with `--confirmed-plan SHA`; a changed family or
header requires a fresh review. The controller also binds the operation to the
current unlocked Oblivion opening.

Before writing, the controller checks each real volume keyslot. It journals
the old and new encrypted wrappers inside the encrypted general archive, then
replaces and reads back each LUKS2 token. The journal contains no plaintext
password or family capability. Once complete, obsolete wrappers are removed
from the journal; the member list and outcome remain inspectable.

## An interrupted change

Do not start another change or guess which password each member now accepts.
Inspect the recorded transaction:

```sh
oblivion safe password status --json
oblivion safe password recover TRANSACTION --complete
oblivion safe password recover TRANSACTION --rollback
```

Choose one recovery direction. Completion requires private `COMPLETE`
confirmation; rollback requires `ROLLBACK`. Recovery checks the entire original
member set and every current header before any writes. A replaced volume or
unknown header stops the operation for inspection. There is no automatic replay
after restart. Declined confirmation returns exit code 130.

While a transaction is pending, affected Safes cannot open, grow, create
children, enter Share or personal backup. Restoring another volume with that
family is also refused until recovery finishes. Unrelated families remain
independent. A pending record is not permission to discard or recreate a Safe.

## What a password change does not revoke

A previously exported personal backup retains its original password. A copied
old LUKS header plus its password can still recover the same unchanged family
capability and data keys. This operation is a password-wrapper update, not
compromise recovery or data-key revocation. Use [Share](SHARING.md) to create
separately keyed portable data; it has a different credential policy.

A child backed up after the change can still be restored independently with
its then-current password, without its mother. Real-LUKS2 regular-file fixtures
cover interrupted completion, rollback, unchanged keys, and standalone child
credentials. Installed-VM cold restore and power-loss qualification remain
release gates.
