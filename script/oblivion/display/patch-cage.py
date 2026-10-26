#!/usr/bin/env python3
"""Small, fail-on-source-change integration against Debian Cage 0.2.0-2."""
from pathlib import Path
import difflib

def replace(text, before, after):
    if text.count(before) != 1:
        raise ValueError(f"Cage source changed around {before!r}")
    return text.replace(before, after, 1)

files = {name: Path(name).read_text() for name in ("seat.c", "seat.h", "cage.c", "meson.build")}
text = files.copy()
text["seat.c"] = replace(text["seat.c"], "#include <stdlib.h>", "#include <stdlib.h>\n#include <stdio.h>\n#include <stdint.h>\n#include <sys/stat.h>")
extra = r'''
/* The controller publishes a compiled XKB map in RAM. Applying a layout must
 * not restart the terminal or interrupt a password/setup form. */
struct oblivion_keyboard {
	struct wlr_keyboard *keyboard;
	struct wl_listener destroy;
	struct wl_list link;
};

static void
oblivion_keyboard_destroy(struct wl_listener *listener, void *data)
{
	struct oblivion_keyboard *item = wl_container_of(listener, item, destroy);
	wl_list_remove(&item->destroy.link);
	wl_list_remove(&item->link);
	free(item);
}

static struct xkb_keymap *
oblivion_keymap(struct xkb_context *context, ino_t *generation)
{
	FILE *file = fopen("/run/oblivion-keymap.xkb", "r");
	if (!file) return xkb_keymap_new_from_names(context, NULL, XKB_KEYMAP_COMPILE_NO_FLAGS);
	struct stat status;
	struct xkb_keymap *map = NULL;
	if (fstat(fileno(file), &status) == 0 && status.st_uid == 0 &&
	    S_ISREG(status.st_mode) && !(status.st_mode & 0022) && status.st_size < 1024 * 1024) {
		map = xkb_keymap_new_from_file(context, file, XKB_KEYMAP_FORMAT_TEXT_V1, XKB_KEYMAP_COMPILE_NO_FLAGS);
		if (map && generation) *generation = status.st_ino;
	}
	fclose(file);
	return map;
}

void
seat_reload_keymap(struct cg_seat *seat)
{
	if (!seat) return;
	struct xkb_context *context = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
	if (!context) return;
	ino_t generation = 0;
	struct xkb_keymap *map = oblivion_keymap(context, &generation);
	if (!map) {
		xkb_context_unref(context);
		return;
	}
	bool applied = true;
	struct oblivion_keyboard *item;
	wl_list_for_each (item, &seat->keyboards, link) {
		applied = wlr_keyboard_set_keymap(item->keyboard, map) && applied;
	}
	xkb_keymap_unref(map);
	xkb_context_unref(context);
	if (!applied || generation == 0) return;
	FILE *ack = fopen("/run/oblivion-display/keymap-applied", "w");
	if (ack) {
		fprintf(ack, "%ju\n", (uintmax_t)generation);
		fclose(ack);
	}
}

'''
text["seat.c"] = replace(text["seat.c"], "static void\nhandle_new_keyboard(", extra + "static void\nhandle_new_keyboard(")
text["seat.c"] = replace(text["seat.c"], "struct xkb_keymap *keymap = xkb_keymap_new_from_names(context, NULL, XKB_KEYMAP_COMPILE_NO_FLAGS);", "struct xkb_keymap *keymap = oblivion_keymap(context, NULL);")
text["seat.c"] = replace(text["seat.c"], "\tcg_keyboard_group_add(keyboard, seat, virtual);", """\tcg_keyboard_group_add(keyboard, seat, virtual);
\tstruct oblivion_keyboard *item = calloc(1, sizeof(*item));
\tif (!item) return;
\titem->keyboard = keyboard;
\titem->destroy.notify = oblivion_keyboard_destroy;
\twl_signal_add(&keyboard->base.events.destroy, &item->destroy);
\twl_list_insert(&seat->keyboards, &item->link);""")
text["seat.h"] = replace(text["seat.h"], "#define DEFAULT_XCURSOR", "struct cg_seat;\nvoid seat_reload_keymap(struct cg_seat *seat);\n\n#define DEFAULT_XCURSOR")
text["cage.c"] = replace(text["cage.c"], "\tswitch (signal) {", "\tswitch (signal) {\n\tcase SIGHUP:\n\t\tseat_reload_keymap(server->seat);\n\t\treturn 0;")
line = "\tstruct wl_event_source *sigterm_source = wl_event_loop_add_signal(event_loop, SIGTERM, handle_signal, &server);"
text["cage.c"] = replace(text["cage.c"], line, line + "\n\tstruct wl_event_source *sighup_source = wl_event_loop_add_signal(event_loop, SIGHUP, handle_signal, &server);")
text["cage.c"] = replace(text["cage.c"], "\twl_event_source_remove(sigint_source);", "\twl_event_source_remove(sighup_source);\n\twl_event_source_remove(sigint_source);")
line = next(line for line in text["meson.build"].splitlines() if line.startswith("have_xwayland ="))
text["meson.build"] = replace(text["meson.build"], line, "# Oblivion runs only a native Wayland terminal.\nhave_xwayland = false")
patch = "".join("".join(difflib.unified_diff(files[name].splitlines(True), changed.splitlines(True), fromfile="a/" + name, tofile="b/" + name)) for name, changed in text.items())
Path("oblivion.patch").write_text(patch)
for name, changed in text.items():
    Path(name).write_text(changed)
