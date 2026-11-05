# Debian Live controls

The current-source Live image boots Debian, starts Oblivion's headless controller
VM and presents the manager in a fullscreen terminal. Debian owns the physical
network, keyboard and time zone. These controls do not live in the Oblivion
Settings menu or in a Safe.

Use the following virtual consoles:

| Shortcut | Debian screen |
| --- | --- |
| **Ctrl+Alt+F1** | Return to Oblivion. |
| **Ctrl+Alt+F2** | NetworkManager's `nmtui`: activate or edit Ethernet and Wi-Fi connections. |
| **Ctrl+Alt+F3** | Keyboard: press Enter to open Debian's `keyboard-configuration` dialog. |
| **Ctrl+Alt+F4** | Time zone: press Enter to open Debian's `tzdata` dialog. |

A keyboard with media keys may also need Fn. If a hypervisor intercepts the
shortcut, use its send-key control. The consoles expose fixed Debian tools;
they do not provide an unauthenticated root shell.

In NetworkManager choose **Activate a connection**, select the Wi-Fi network and
enter its password there. Ethernet normally obtains its settings automatically
when a cable is connected. This configures the underlying computer's link;
Safe traffic still uses its own verified Tor/SOCKS5 gateway and policy.

Complete one keyboard or time-zone dialog before starting the other: both use
Debian's configuration database. Keyboard changes update the Linux consoles and
the existing Cage terminal without restarting the manager, controller or Safe.
There is no separate Oblivion keyboard catalog or saved OS-settings profile.

**OS preferences last for this boot.** Debian's live root overlay is volatile.
Wi-Fi credentials stay in NetworkManager's RAM directory; keyboard and time-zone
changes stay in the RAM overlay. They are not written into Oblivion's encrypted
archive. The dedicated boot-media data partition stores only the controller's
encrypted Oblivion data. Reopening that data restores application settings,
Safes, conversations and files, rather than the previous physical machine's OS
configuration.

The clock starts from the computer's RTC or the hypervisor's clock. Automatic
NTP remains disabled; this increment adds no external clock or IP-check service.
A time-zone change does not correct a wrong date or clock. Set the firmware or
hypervisor clock correctly before booting: incorrect time can prevent TLS and
Tor from connecting. Any future automatic clock-network policy is a separate
product decision.

Changing virtual consoles does not close a Safe. Oblivion's existing inactivity
locks continue to apply while its screen is in the background.

Open **System** with **F3** to inspect removable USB media. The list shows
available partitions and unpartitioned USB disks, their sizes and whether
the kernel reports them as read-only. Connect or remove a drive, then press
**R** to refresh. The boot drive and devices in use are excluded. The same
inventory is available through `oblivion runtime live-media --json`.

In the 1.0 source, open a Safe's **Files → Import from USB**, then choose a
device. The isolated transfer VM browses ext4, FAT or exFAT media in read-only
mode. Use **Space** to select and **C** to continue. Choose the workspace name
and approve the file manifest. Wait for the verified result before removing the
USB. If removal cannot be confirmed, check the runtime and the recorded copy
outcome before retrying.

**Files → Export to USB** starts in the Safe file picker. Choose the files,
select a writable USB, then use **Write to USB** on the manifest review. Only
then does the isolated writer get write access. The files are readable outside
the Safe in `/Oblivion-<operation>/files`. Each export gets its own folder.
Wait for the verified removal message before disconnecting the drive.

The CLI accepts `oblivion files export --safe SAFE --path workspace/FILE
--usb ID` and shows the same review. The 1.0 source targets ext4, FAT and
exFAT. FAT has a per-file size limit. The current manager retains confirmed
USB receipts for this run.

After interruption or a manager restart, open **Files → Transfers and
recovery → USB exports** and select the connected device again. A recent USB
operation also offers **Inspect USB**. Inspection opens the drive read-only,
lists operation IDs, and checks the selected operation's current contents
against the manifest on that drive. If staging verifies in full, **Publish
verified copy** completes the same export without copying the Safe files
again. **Discard staging** removes only reviewed staging. Each change requires
confirmation, a fresh check in the isolated writer, and verified device
removal. Files already published are left in place.

With the Safe open, the equivalent commands are `oblivion files transfers
--safe SAFE --usb DEVICE` and `oblivion files status --safe SAFE --usb DEVICE
--operation ID`. Replace `status` with `recover` or `discard` to review and
confirm a change in the terminal. Find the current device ID with
`oblivion runtime live-media --json`.

Verification checks the files against the selected USB's own manifest. If the
record cannot be verified, leave it untouched. Inspection of ext4 does not
replay the journal, so an interrupted write can leave an outcome unconfirmed.
Acceptance on physical ext4, FAT and exFAT devices, unplug and power loss
remain open.

To switch between persistent and RAM-only storage, lock Oblivion and choose
**Change storage mode** on its welcome screen. The action is available only
after active work is closed and no runtime recovery is pending. It stops the
controller and clears the current Live storage selection; existing encrypted
data on the boot device is preserved. On the closed display, press **R** to
start Oblivion and choose the next mode. Closing the manager otherwise leaves
that display waiting for R; it does not open a host shell or restart immediately.
If the action fails, the manager shows an error and waits for an explicit R
before inspecting the runtime again.

These are source features awaiting the Live hardware acceptance described in the
[roadmap](oblivion1.0-roadmap.md). They do not qualify a published ISO by themselves.

If the launcher cannot start, its diagnostics stay visible in the terminal.
Press **R** to retry after correcting the problem, or **Ctrl+Q** to pause while
using the Debian consoles. A normal manager exit also waits for R; it does not
immediately restart the setup or repeatedly initialize storage. These diagnostics
are terminal output and are not saved as a disk log.

New USB preparation writes and flushes the runtime identity into the reviewed
free extent before publishing its partition-table entry. If setup stops after
the table is written but before kernel partition discovery, the next boot can
recognize that identity. Existing partitions and their data are preserved.
Unknown partitions are still refused, rather than automatically formatted or
treated as an interrupted Oblivion setup. This ordering is covered with real
`sfdisk` on sparse files; power-loss recovery on physical USB remains a gate.

Debian interfaces: [NetworkManager](https://manpages.debian.org/trixie/network-manager/nmtui.1.en.html),
[keyboard configuration](https://manpages.debian.org/trixie/keyboard-configuration/keyboard.5.en.html),
[console keymap application](https://manpages.debian.org/trixie/console-setup/setupcon.1.en.html),
[Cage keyboard environment](https://manpages.debian.org/trixie/cage/cage.1.en.html).
