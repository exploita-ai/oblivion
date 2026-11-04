# termcn FilePicker

Upstream: https://github.com/shadcn-labs/termcn

Revision: `fd28627bb340f5eaa1a5824d47db6373a739d95a`

Source: `apps/web/registry/bases/opentui/ui/file-picker.tsx`

License: MIT, copyright 2026 Aniket Pawar; retained in LICENSE.

The directory picker is adapted to Solid (the renderer used by OpenCode), with
controlled directory metadata instead of local filesystem access. Selection,
focus, viewport scrolling and keyboard navigation use OpenTUI's Select component.
Oblivion adds controlled selection across directories, pagination and file sizes.
The explicit local import chooser supplies local metadata; Safe metadata comes
from the controller and guest, which enforce workspace/imports boundaries. The
picker receives metadata only and does not open or share any filesystem.
The caller also supplies the displayed directory and exact parent destination:
the local chooser uses the native path API, while the Safe chooser uses POSIX
paths. The picker does not infer path separators or rewrite Windows drive paths.
