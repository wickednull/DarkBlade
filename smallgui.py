import tkinter as tk
import tkinter.font as tkfont
import ttkbootstrap as tb

# Import the full-featured GUI without removing anything
from installer_gui import USBArmyKnifeInstaller

class SmallScreenInstaller(USBArmyKnifeInstaller):
    def __init__(self):
        super().__init__()
        # Fit to small screens and make touch targets usable while conserving space
        try:
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            # Use entire screen by default on small devices
            self.geometry(f"{sw}x{sh}+0+0")
            # Slight downscale of font metrics to fit more content
            try:
                # 0.85 keeps readability on 5"-7" displays
                self.tk.call('tk', 'scaling', 0.85)
            except Exception:
                pass
            # Reduce default paddings and fonts in styles
            style = tb.Style()
            style.configure("TButton", padding=6, font=("Arial", 9))
            style.configure("Action.TButton", padding=7, font=("Arial", 10, "bold"))
            style.configure("TLabel", font=("Arial", 9))
            style.configure("Title.TLabel", font=("Arial", 12, "bold"))
            style.configure("TNotebook.Tab", padding=[8, 4])
        except Exception:
            pass

        # Install compact tab navigator (dropdown + prev/next), keep all features
        try:
            self._capture_full_tab_titles()
            self._install_tab_navigator()
            self._compactify_tabs_to_icons()
            self._hide_notebook_tabs()
        except Exception:
            pass

        # Shrink widget fonts to fit vertically while keeping everything accessible
        try:
            self._shrink_all_widget_fonts(self, factor=0.9, min_size=8)
        except Exception:
            pass

    def _shrink_all_widget_fonts(self, root, factor=0.9, min_size=8):
        def shrink_font(font_desc):
            try:
                f = tkfont.Font(root=root, font=font_desc)
                size = f['size']
                if isinstance(size, str):
                    try:
                        size = int(size)
                    except Exception:
                        size = 10
                if size == 0:
                    return  # named size, skip
                if size < 0:
                    # pixel size (negative); scale and keep negative
                    new_size = -max(min_size, int(abs(size) * factor))
                else:
                    new_size = max(min_size, int(size * factor))
                f.configure(size=new_size)
                return f
            except Exception:
                return None

        def walk(w):
            try:
                # Ttk widgets often ignore direct font; still try for tk.Text/Entry/Label
                if 'font' in w.keys():
                    f = w.cget('font')
                    if f:
                        nf = shrink_font(f)
                        if nf is not None:
                            try:
                                w.configure(font=nf)
                            except Exception:
                                pass
            except Exception:
                pass
            for child in w.winfo_children():
                walk(child)
        walk(root)

    # ----- Small-screen tab fixes -----
    def _capture_full_tab_titles(self):
        self._tab_full_titles = {}
        try:
            for tid in self.notebook.tabs():
                self._tab_full_titles[tid] = self.notebook.tab(tid, 'text') or ''
        except Exception:
            pass

    def _install_tab_navigator(self):
        # Create a compact navigation bar above the Notebook with prev/next and a dropdown of full tab names
        try:
            # Re-pack to insert nav bar above
            try:
                self.notebook.pack_forget()
            except Exception:
                pass
            nav = tb.Frame(self, padding=4)
            nav.pack(fill=tb.X)
            self._tabnav = nav

            tb.Button(nav, text='◀', width=3, command=lambda: self._step_tab(-1)).pack(side=tb.LEFT, padx=2)

            titles = [self._tab_full_titles.get(t, '') for t in self.notebook.tabs()]
            self._tab_combo_var = tk.StringVar()
            self._tab_combo = tb.Combobox(nav, state='readonly', values=titles, textvariable=self._tab_combo_var)
            self._tab_combo.pack(side=tb.LEFT, fill=tb.X, expand=True)
            self._tab_combo.bind('<<ComboboxSelected>>', lambda e: self._select_tab_by_title(self._tab_combo_var.get()))

            tb.Button(nav, text='▶', width=3, command=lambda: self._step_tab(1)).pack(side=tb.LEFT, padx=2)

            # Re-pack notebook below nav
            self.notebook.pack(fill=tb.BOTH, expand=True)

            # Sync selection
            self.notebook.bind('<<NotebookTabChanged>>', self._on_tab_changed)
            self._on_tab_changed(None)
        except Exception:
            pass

    def _compactify_tabs_to_icons(self):
        # Replace tab labels with their leading emoji or first 2 chars to save space; keep full names in dropdown
        try:
            for tid in self.notebook.tabs():
                full = self._tab_full_titles.get(tid, '')
                short = full
                if full:
                    tok = full.split()[0]
                    short = tok if tok else full[:2]
                self.notebook.tab(tid, text=short)
        except Exception:
            pass

    def _hide_notebook_tabs(self):
        # Hide the native tab bar; navigation is handled by dropdown and prev/next
        try:
            style = tb.Style()
            # Clone notebook layout and create a variant with no Tab element
            try:
                base_layout = style.layout('TNotebook')
                style.layout('NoTabs.TNotebook', base_layout)
            except Exception:
                # Fallback: ensure style exists even if cloning fails
                style.layout('NoTabs.TNotebook', [])
            # Remove tab element layout so tabs are not rendered
            style.layout('NoTabs.TNotebook.Tab', [])
            # Apply style to our notebook
            self.notebook.configure(style='NoTabs.TNotebook')
        except Exception:
            pass

    def _select_tab_by_title(self, title: str):
        try:
            for tid, full in self._tab_full_titles.items():
                if full == title:
                    self.notebook.select(tid)
                    break
        except Exception:
            pass

    def _on_tab_changed(self, event):
        try:
            cur = self.notebook.select()
            full = self._tab_full_titles.get(cur, '')
            if hasattr(self, '_tab_combo_var'):
                self._tab_combo_var.set(full)
        except Exception:
            pass

    def _step_tab(self, delta: int):
        try:
            tabs = self.notebook.tabs()
            cur = self.notebook.select()
            if cur in tabs:
                i = tabs.index(cur)
                i = (i + delta) % len(tabs)
                self.notebook.select(tabs[i])
        except Exception:
            pass


def main():
    app = SmallScreenInstaller()
    app.mainloop()


if __name__ == "__main__":
    main()
