# TUI Experiments

- Temporary, opt-in UI experiments belong in the `experiments` registry in `src/component/dialog-experiments.tsx`, with behavior gated by the matching `config.experimental` key.
- The Experiments framework is permanent infrastructure. Keep the registry, dialog, settings persistence, toggle handling, and UI entry point even when there are no active experiments.
- Graduating an experiment means removing only its registry entry and feature-specific gate, making that feature's behavior unconditional. Abandoning an experiment means removing its entry, gate, and experimental behavior.
- Do not remove or simplify away the reusable Experiments infrastructure because the registry is empty. An empty registry is intentional and ready for future experiments, not dead code.

# Oblivion Chat UI

- For Oblivion-specific changes, preserve OpenCode's production chat components, layout and established interactions. Reuse the existing prompt, message rendering, streaming, scrolling, tool displays and permission dialogs; do not build visual copies or redesign the chat.
- Limit UI customization to removing unneeded commands or sections, light branding, and the integration hooks required for Oblivion's protected-session lifecycle. Keep using semantic theme tokens and existing components.
- The trusted host session manager is a separate interface for volumes, credentials, network and transfers. New administrative screens belong there; they do not require replacing the guest chat UI.
