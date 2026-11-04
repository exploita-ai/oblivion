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

These are source features awaiting the Live hardware acceptance described in the
[roadmap](oblivion1.0-roadmap.md). They do not qualify a published ISO by themselves.

Debian interfaces: [NetworkManager](https://manpages.debian.org/trixie/network-manager/nmtui.1.en.html),
[keyboard configuration](https://manpages.debian.org/trixie/keyboard-configuration/keyboard.5.en.html),
[console keymap application](https://manpages.debian.org/trixie/console-setup/setupcon.1.en.html),
[Cage keyboard environment](https://manpages.debian.org/trixie/cage/cage.1.en.html).
