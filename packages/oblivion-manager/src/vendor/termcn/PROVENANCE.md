# termcn FilePicker

Upstream: https://github.com/shadcn-labs/termcn

Revision: `fd28627bb340f5eaa1a5824d47db6373a739d95a`

Source: `apps/web/registry/bases/opentui/ui/file-picker.tsx`

License: MIT, copyright 2026 Aniket Pawar; retained in LICENSE.

The directory picker is adapted to Solid (the renderer used by OpenCode), with
controlled directory metadata instead of local filesystem access. Selection,
focus, viewport scrolling and keyboard navigation use OpenTUI's Select component.
Oblivion adds multiple selection, pagination and file sizes. The controller and
guest enforce the allowed roots; the picker receives metadata only.
