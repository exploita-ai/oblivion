"""One-shot desktop path selection. The TUI still owns all copy approval."""

import json
import os
import select
import socket
import stat
import sys


def local_paths(files):
    paths = []
    size = 0
    for file in files:
        path = file.get_path()
        if path is None or not os.path.isabs(path) or any(
            ord(char) < 32 or 127 <= ord(char) <= 159
            or 0x202A <= ord(char) <= 0x202E or 0x2066 <= ord(char) <= 0x2069
            for char in path
        ):
            raise ValueError
        size += len(path.encode("utf-8"))
        if len(paths) == 128 or size > 64 * 1024:
            raise ValueError
        paths.append(path)
    return paths


def select_paths():
    mode = os.fstat(0).st_mode
    if stat.S_ISSOCK(mode):
        with socket.socket(fileno=os.dup(0)) as owner:
            if owner.family != socket.AF_UNIX or owner.type != socket.SOCK_STREAM:
                raise RuntimeError
    elif not stat.S_ISFIFO(mode):
        raise RuntimeError
    ready = select.poll()
    ready.register(0, select.POLLIN)
    if ready.poll(0):
        return []

    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Gdk", "4.0")
    from gi.repository import Gdk, GLib, Gtk

    settings = Gtk.Settings.get_default()
    if not hasattr(Gdk, "FileList") or settings is None:
        raise RuntimeError
    # GTK validates its application name before checking the recent-file setting.
    GLib.set_application_name("Oblivion")
    settings.set_property("gtk-recent-files-enabled", False)

    loop = GLib.MainLoop()
    selected = []
    window = Gtk.Window(title="Oblivion · Import files", default_width=480)
    body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
    for edge in ("top", "bottom", "start", "end"):
        body.set_property("margin-" + edge, 24)
    window.set_child(body)
    body.append(Gtk.Label(label="Drop files or folders here"))
    message = Gtk.Label(label="Review your selection in Oblivion before copying.", wrap=True)
    body.append(message)

    def finish(paths):
        selected[:] = paths
        loop.quit()

    def cancel(*_):
        finish([])
        return False

    def accept(files):
        try:
            paths = local_paths(files)
        except ValueError:
            message.set_text("Choose up to 128 local paths with valid names and a combined length under 64 KiB.")
            return False
        if not paths:
            return False
        finish(paths)
        return True

    def dropped(_target, file_list, _x, _y):
        return accept(file_list.get_files())

    def choose(_button, folder):
        action = Gtk.FileChooserAction.SELECT_FOLDER if folder else Gtk.FileChooserAction.OPEN
        # Keep the chooser in this process so its settings and recents stay local.
        chooser = Gtk.FileChooserDialog(
            title="Choose folder" if folder else "Choose files",
            transient_for=window, destroy_with_parent=True, modal=True, action=action,
        )
        chooser.add_button("Cancel", Gtk.ResponseType.CANCEL)
        chooser.add_button("Choose", Gtk.ResponseType.ACCEPT)
        chooser.set_default_response(Gtk.ResponseType.ACCEPT)
        chooser.set_create_folders(False)
        chooser.set_select_multiple(not folder)

        def response(dialog, choice):
            if choice == Gtk.ResponseType.ACCEPT:
                model = dialog.get_files()
                accept(model.get_item(index) for index in range(model.get_n_items()))
            dialog.destroy()

        chooser.connect("response", response)
        chooser.present()

    drop = Gtk.DropTarget.new(Gdk.FileList.__gtype__, Gdk.DragAction.COPY)
    drop.connect("drop", dropped)
    window.add_controller(drop)
    keys = Gtk.EventControllerKey()

    def key_pressed(_controller, keyval, _keycode, _state):
        if keyval != Gdk.KEY_Escape:
            return False
        cancel()
        return True

    keys.connect("key-pressed", key_pressed)
    window.add_controller(keys)
    buttons = Gtk.Box(spacing=8, halign=Gtk.Align.CENTER)
    for label, folder in (("Choose files", False), ("Choose folder", True)):
        button = Gtk.Button(label=label)
        button.connect("clicked", choose, folder)
        buttons.append(button)
    cancel_button = Gtk.Button(label="Cancel")
    cancel_button.connect("clicked", cancel)
    buttons.append(cancel_button)
    body.append(buttons)
    window.connect("close-request", cancel)

    owner = GLib.IOChannel.unix_new(0)
    GLib.io_add_watch(owner, GLib.PRIORITY_HIGH,
                      GLib.IOCondition.IN | GLib.IOCondition.HUP | GLib.IOCondition.ERR | GLib.IOCondition.NVAL,
                      cancel)
    window.present()
    loop.run()
    window.destroy()
    return selected


if __name__ == "__main__":
    try:
        paths = select_paths()
    except (ImportError, OSError, RuntimeError, ValueError):
        print("desktop_file_picker_unavailable", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"paths": paths}, ensure_ascii=False, separators=(",", ":")), flush=True)
