"""Qt6 shared helpers for the Minecraft Server Scanner (PySide6 port).

Single responsibility: generic Qt infrastructure with NO scanner-backend
imports (so scanner.py can import this module without import cycles).

Contents:
  - thread-safe ``ui_after(ms, func)`` (safe to call from worker threads)
  - ``QtBaseMixin`` (``after`` + ``set_status``)
  - ``ResultTable`` (QTableWidget with a tkinter-Treeview-compatible API)
  - ``make_table_sortable`` / ``make_tree_sortable`` (custom key sorting)
  - dialogs: ``q_info``, ``q_error``, ``q_ask_string``, ``q_ask_open``,
    ``q_ask_save``, ``ask_reason_with_whitelist``,
    ``ensure_shodan_key_ui``, ``SudoPasswordDialog``
"""

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


# ---------------------------------------------------------------------------
# Thread-safe UI dispatch (replaces tkinter ``widget.after(0, func)``)
# ---------------------------------------------------------------------------

class _UiDispatcher(QObject):
    _post = Signal(object, int)

    def __init__(self):
        super().__init__()
        self._post.connect(self._on_post, Qt.QueuedConnection)

    def _on_post(self, func, ms):
        try:
            QTimer.singleShot(int(ms), func)
        except Exception:
            pass


_DISPATCHER = None


def _dispatcher():
    global _DISPATCHER
    if _DISPATCHER is None:
        _DISPATCHER = _UiDispatcher()
        try:
            app = QApplication.instance()
            if app is not None:
                _DISPATCHER.moveToThread(app.thread())
        except Exception:
            pass
    return _DISPATCHER


def ui_after(ms, func):
    """Schedule ``func`` on the GUI thread (safe from worker threads)."""
    try:
        app = QApplication.instance()
        if app is not None and QThread.currentThread() != app.thread():
            _dispatcher()._post.emit(func, int(ms))
            return
    except Exception:
        pass
    try:
        QTimer.singleShot(int(ms), func)
    except Exception:
        try:
            func()
        except Exception:
            pass


class QtBaseMixin:
    """Provides tkinter-like ``after`` plus status-label syncing."""

    status_text = "Ready."

    def after(self, ms, func):
        ui_after(ms, func)

    def set_status(self, msg):
        self.status_text = msg
        try:
            self.status_label.setText(msg)
        except Exception:
            pass

    # compat: some code paths call ``_set_status``
    def _set_status(self, msg):
        self.set_status(msg)


# ---------------------------------------------------------------------------
# ResultTable — QTableWidget with a Treeview-compatible API
# ---------------------------------------------------------------------------

def _default_sort_key(col):
    """Faithful default sort keys mirroring the Tk port's key funcs."""
    import re as _re

    c = str(col).lower()

    if c == "ip":
        def _ip(v):
            s = str(v)
            try:
                host, port = s.split(":")
                port = int(port)
            except Exception:
                host, port = s, 0
            parts = host.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                try:
                    return tuple(int(p) for p in parts) + (port,)
                except Exception:
                    return (0, 0, 0, 0, port)
            return (999, 999, 999, 999, str(host), port)
        return _ip
    if c == "players":
        def _pl(v):
            try:
                return int(str(v).split("/", 1)[0])
            except Exception:
                return -1
        return _pl
    if c == "version":
        def _ver(v):
            t = []
            for token in str(v).strip().split("."):
                if token.isdigit():
                    t.append(int(token))
                else:
                    nums = _re.findall(r"\d+", token)
                    t.extend(int(x) for x in nums) if nums else t.append(0)
            return tuple(t) if t else (0,)
        return _ver
    if c == "cracked":
        def _cr(v):
            s = str(v).lower()
            if s in ("false", "no", "0", "", "unknown"):
                return 0 if s in ("false", "no", "0") else 2
            return 1
        return _cr
    return lambda v: str(v).lower()


class ResultTable(QTableWidget):
    """QTableWidget exposing the tkinter Treeview calls used by the app.

    Supported (superset of every call site in the ported tabs):
      set_columns(cols), columns, set_sort_keys(dict),
      insert("", "end", values=row)->iid, delete(*iids), clear(),
      get_children(item="")->list, selection()->list,
      selection_set(iids), selection_remove(iids), focus(iid), see(iid),
      item(iid)->dict, item(iid,"values")->tuple,
      item(iid, values=...), set(iid, col, val),
      set_row_icon(iid, QIcon), find_rows_containing(col, query),
      column_width(col, width)
    """

    def __init__(self, parent=None, columns=(), headers=None):
        # tolerate the (columns, parent) argument order used by some call sites
        if isinstance(parent, (list, tuple)) and (
            columns is None or isinstance(columns, QWidget) or columns == ()
        ):
            columns, parent = parent, (columns if isinstance(columns, QWidget) else None)
        if parent is not None and not isinstance(parent, QWidget):
            # e.g. a stray columns tuple passed as parent with real parent 2nd
            try:
                columns, parent = parent, columns
                if not isinstance(parent, (QWidget, type(None))):
                    parent = None
            except Exception:
                parent = None
        super().__init__(parent if isinstance(parent, QWidget) else None)
        self._columns = tuple(columns)
        self._iid_counter = 0
        self._iids = []          # row order -> iid
        self._values = {}        # iid -> tuple values
        self._icons = {}         # iid -> QIcon
        self._sort_keys = {}
        self._sort_state = {}    # col -> bool (next reverse flag)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.ExtendedSelection)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        if self._columns:
            self._apply_columns(headers)
        try:
            hdr = self.horizontalHeader()
            hdr.sectionClicked.connect(self._on_header_clicked)
            hdr.setSectionsClickable(True)
        except Exception:
            pass

    # -- columns ------------------------------------------------------
    def _apply_columns(self, headers=None):
        self.setColumnCount(len(self._columns))
        if headers is None:
            headers = [str(c).upper() for c in self._columns]
        self.setHorizontalHeaderLabels(list(headers))

    def set_columns(self, cols):
        self._columns = tuple(cols)
        self._sort_state = {}
        self._apply_columns()
        self.clear_contents()

    @property
    def columns(self):
        return self._columns

    def __getitem__(self, key):
        if key == "columns":
            return self._columns
        raise KeyError(key)

    def __setitem__(self, key, value):
        if key == "columns":
            self.set_columns(value)
            return
        raise KeyError(key)

    def set_sort_keys(self, key_funcs):
        self._sort_keys = dict(key_funcs or {})

    def column_width(self, col, width):
        try:
            idx = self._columns.index(col) if isinstance(col, str) else int(col)
            self.setColumnWidth(idx, int(width))
        except Exception:
            pass

    def setSortingEnabled(self, enabled):
        # Custom key-based header sorting (see _on_header_clicked) stays
        # authoritative so IP/players/version order matches the original app.
        try:
            super().setSortingEnabled(False)
        except Exception:
            pass

    # -- rows ---------------------------------------------------------
    def _new_iid(self):
        self._iid_counter += 1
        return f"r{self._iid_counter}"

    def insert(self, parent_ignored="", index_ignored="end", values=(), **kw):
        if kw and "values" in kw:
            values = kw["values"]
        vals = tuple("" if v is None else str(v) for v in (values or ()))
        # pad/truncate to column count
        n = len(self._columns)
        if len(vals) < n:
            vals = vals + ("",) * (n - len(vals))
        elif len(vals) > n and n:
            vals = vals[:n]
        iid = self._new_iid()
        row = len(self._iids)
        self._iids.append(iid)
        self._values[iid] = vals
        self.insertRow(row)
        for c, v in enumerate(vals):
            item = QTableWidgetItem(v)
            try:
                if iid in self._icons and c == 0:
                    from PySide6.QtGui import QIcon

                    icon = self._icons[iid]
                    if isinstance(icon, QIcon):
                        item.setIcon(icon)
            except Exception:
                pass
            self.setItem(row, c, item)
        return iid

    def _row_of(self, iid):
        try:
            return self._iids.index(iid)
        except ValueError:
            return -1

    def delete(self, *iids):
        if not iids:
            return
        # delete descending so indices stay valid
        rows = sorted(
            (self._row_of(i) for i in iids), reverse=True
        )
        for r in rows:
            if r >= 0:
                try:
                    self.removeRow(r)
                except Exception:
                    pass
                try:
                    gone = self._iids.pop(r)
                    self._values.pop(gone, None)
                    self._icons.pop(gone, None)
                except Exception:
                    pass

    def clear_contents(self):
        try:
            self.setRowCount(0)
        except Exception:
            pass
        self._iids = []
        self._values = {}
        self._icons = {}

    def clear(self):
        self.clear_contents()

    def get_children(self, item=""):
        return list(self._iids)

    # -- selection ----------------------------------------------------
    def selection(self):
        try:
            rows = sorted({i.row() for i in self.selectedIndexes()})
            return [self._iids[r] for r in rows if 0 <= r < len(self._iids)]
        except Exception:
            return []

    def selection_set(self, iids):
        try:
            self.clearSelection()
            if isinstance(iids, str):
                iids = [iids]
            for iid in iids or []:
                r = self._row_of(iid)
                if r >= 0:
                    self.selectRow(r)
        except Exception:
            pass

    def selection_remove(self, iids):
        try:
            if isinstance(iids, str):
                iids = [iids]
            sm = self.selectionModel()
            for iid in iids or []:
                r = self._row_of(iid)
                if r >= 0:
                    for c in range(self.columnCount()):
                        idx = self.model().index(r, c)
                        sm.select(idx, sm.Deselect | sm.Rows)
        except Exception:
            pass

    def focus(self, iid):
        try:
            r = self._row_of(iid)
            if r >= 0:
                self.setCurrentCell(r, 0)
        except Exception:
            pass

    def see(self, iid):
        try:
            r = self._row_of(iid)
            if r >= 0 and self.columnCount() > 0:
                it = QTableWidget.item(self, r, 0)
                if it is not None:
                    self.scrollToItem(it)
        except Exception:
            pass

    # -- values -------------------------------------------------------
    def item(self, iid, option=None, **kw):
        if "values" in kw:
            vals = tuple("" if v is None else str(v) for v in (kw["values"] or ()))
            n = len(self._columns)
            if len(vals) < n:
                vals = vals + ("",) * (n - len(vals))
            elif len(vals) > n and n:
                vals = vals[:n]
            self._values[iid] = vals
            r = self._row_of(iid)
            if r >= 0:
                for c, v in enumerate(vals):
                    try:
                        it = QTableWidget.item(self, r, c)
                        if it is None:
                            it = QTableWidgetItem(v)
                            self.setItem(r, c, it)
                        else:
                            it.setText(v)
                    except Exception:
                        pass
            return {}
        # image/text kwargs from tkinter port: ignore (icons via set_row_icon)
        if kw:
            return {}
        vals = tuple(self._values.get(iid, ()))
        if option is None:
            return {"values": vals}
        if option == "values":
            return vals
        return ""

    def set(self, iid, column, value):
        try:
            vals = list(self._values.get(iid, ()))
            if isinstance(column, str):
                idx = self._columns.index(column)
            else:
                idx = int(column)
            while len(vals) <= idx:
                vals.append("")
            vals[idx] = "" if value is None else str(value)
            self._values[iid] = tuple(vals)
            r = self._row_of(iid)
            if r >= 0:
                it = QTableWidget.item(self, r, idx)
                if it is None:
                    self.setItem(r, idx, QTableWidgetItem(vals[idx]))
                else:
                    it.setText(vals[idx])
        except Exception:
            pass

    def set_row_icon(self, iid, icon):
        try:
            self._icons[iid] = icon
            r = self._row_of(iid)
            if r >= 0:
                it = QTableWidget.item(self, r, 0)
                if it is not None:
                    it.setIcon(icon)
        except Exception:
            pass

    def find_rows_containing(self, col, query):
        """Return iids whose cell in column ``col`` contains ``query`` (ci)."""
        try:
            if isinstance(col, str):
                col = self._columns.index(col)
            q = str(query).lower()
            out = []
            for iid in self._iids:
                vals = self._values.get(iid, ())
                if col < len(vals) and q in str(vals[col]).lower():
                    out.append(iid)
            return out
        except Exception:
            return []

    # -- sorting ------------------------------------------------------
    def _on_header_clicked(self, logical):
        try:
            cols = self._columns
            if not cols or logical >= len(cols):
                return
            col = cols[logical]
            keyfn = self._sort_keys.get(col) or _default_sort_key(col)
            reverse = self._sort_state.get(col, False)
            keys = []
            for iid in self._iids:
                vals = self._values.get(iid, ())
                v = vals[logical] if logical < len(vals) else ""
                try:
                    keys.append((keyfn(v), iid))
                except Exception:
                    keys.append((str(v), iid))
            keys.sort(key=lambda t: t[0], reverse=reverse)
            order = [iid for _, iid in keys]
            icons = dict(self._icons)
            values = dict(self._values)
            self.setRowCount(0)
            self._iids = []
            for iid in order:
                vals = values.get(iid, ())
                row = len(self._iids)
                self._iids.append(iid)
                self.insertRow(row)
                for c, v in enumerate(vals):
                    it2 = QTableWidgetItem(v)
                    try:
                        if iid in icons and c == 0:
                            it2.setIcon(icons[iid])
                    except Exception:
                        pass
                    self.setItem(row, c, it2)
            self._sort_state[col] = not reverse
            try:
                self.horizontalHeader().setSortIndicator(
                    logical,
                    Qt.DescendingOrder if reverse else Qt.AscendingOrder,
                )
                self.horizontalHeader().setSortIndicatorShown(True)
            except Exception:
                pass
        except Exception:
            pass


def make_table_sortable(table, column_key_funcs):
    """Attach custom-key header sorting (Qt equivalent of make_tree_sortable)."""
    try:
        table.set_sort_keys(column_key_funcs)
    except Exception:
        pass


# tkinter-compat alias (some ported code imports this name from scanner)
def make_tree_sortable(table, column_key_funcs):
    make_table_sortable(table, column_key_funcs)


# ---------------------------------------------------------------------------
# Dialogs (QMessageBox / QInputDialog / QFileDialog equivalents)
# ---------------------------------------------------------------------------

def q_info(parent, title, msg):
    try:
        QMessageBox.information(parent, title, msg)
    except Exception:
        pass


def q_error(parent, title, msg):
    try:
        QMessageBox.critical(parent, title, msg)
    except Exception:
        pass


def q_ask_string(parent, title, prompt, show=None, initialvalue=""):
    try:
        if show == "*":
            text, ok = QInputDialog.getText(
                parent, title, prompt, QLineEdit.Password, str(initialvalue or "")
            )
        else:
            text, ok = QInputDialog.getText(
                parent, title, prompt, QLineEdit.Normal, str(initialvalue or "")
            )
        return text if ok else None
    except Exception:
        return None


def q_ask_open(parent, title, filters="All files (*.*)"):
    try:
        path, _ = QFileDialog.getOpenFileName(parent, title, "", filters)
        return path or ""
    except Exception:
        return ""


def q_ask_save(parent, title, default_name="", filters="All files (*.*)"):
    try:
        path, _ = QFileDialog.getSaveFileName(parent, title, default_name, filters)
        return path or ""
    except Exception:
        return ""


def ask_reason_with_whitelist(parent, title="Reason", prompt="Why ignore? (optional)"):
    """Qt port of the tkinter reason dialog (OK / White List / Cancel)."""
    try:
        dlg = QDialog(parent)
        dlg.setWindowTitle(title)
        dlg.setModal(True)
        try:
            dlg.setFixedSize(460, 130)
        except Exception:
            pass
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel(prompt))
        edit = QLineEdit(dlg)
        lay.addWidget(edit)
        try:
            edit.setFocus()
        except Exception:
            pass
        btns = QHBoxLayout()
        lay.addLayout(btns)
        result = {"value": None}

        def close_with(val):
            result["value"] = None if val is None else str(val)
            try:
                dlg.accept()
            except Exception:
                pass

        b_ok = QPushButton("OK")
        b_ok.clicked.connect(
            lambda: close_with(edit.text().strip() if edit.text().strip() else "")
        )
        b_wl = QPushButton("White List")
        b_wl.clicked.connect(lambda: close_with("White List"))
        b_cancel = QPushButton("Cancel")
        b_cancel.clicked.connect(lambda: close_with(None))
        btns.addWidget(b_ok)
        btns.addWidget(b_wl)
        btns.addWidget(b_cancel)
        dlg.exec()
        return result["value"]
    except Exception:
        return None


def ensure_shodan_key_ui(parent):
    """Qt port: prompt for the Shodan key when no key file exists."""
    import os as _os

    path = _os.path.join(_os.getcwd(), "shodan_key.txt")
    try:
        if _os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                k = f.readline().strip()
                if k:
                    return k
    except Exception:
        pass
    text, ok = QInputDialog.getText(
        parent, "Shodan API Key", "Enter your Shodan API key:", QLineEdit.Password
    )
    if ok and text and text.strip():
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text.strip() + "\n")
        except Exception:
            pass
        return text.strip()
    return None


class SudoPasswordDialog(QDialog):
    """Password prompt for privileged masscan runs (Qt port of the
    hand-built tkinter prompt)."""

    DEFAULT_MESSAGE = (
        "masscan needs raw-socket privileges.\n"
        "Enter your sudo password to rerun discovery with sudo\n"
        "(used once for this scan, never stored):"
    )

    def __init__(self, parent=None, message=None):
        super().__init__(parent)
        self.setWindowTitle("masscan needs root")
        self.setModal(True)
        try:
            self.setWindowFlags(
                self.windowFlags() | Qt.WindowStaysOnTopHint
            )
        except Exception:
            pass
        lay = QVBoxLayout(self)
        label = QLabel(message or self.DEFAULT_MESSAGE)
        try:
            label.setWordWrap(True)
        except Exception:
            pass
        lay.addWidget(label)
        self.entry = QLineEdit(self)
        try:
            self.entry.setEchoMode(QLineEdit.Password)
        except Exception:
            pass
        lay.addWidget(self.entry)
        try:
            self.entry.setFocus()
        except Exception:
            pass
        btns = QHBoxLayout()
        lay.addLayout(btns)
        b_ok = QPushButton("OK")
        b_ok.clicked.connect(self._on_ok)
        b_cancel = QPushButton("Cancel")
        b_cancel.clicked.connect(self._on_cancel)
        btns.addWidget(b_ok)
        btns.addWidget(b_cancel)
        # Return/Escape behave like the OK/Cancel buttons.
        try:
            b_ok.setDefault(True)
        except Exception:
            pass
        self._password = None

    def keyPressEvent(self, event):
        try:
            if event.key() == Qt.Key_Escape:
                self._on_cancel()
                return
        except Exception:
            pass
        try:
            super().keyPressEvent(event)
        except Exception:
            pass

    def _on_ok(self):
        try:
            self._password = self.entry.text()
        except Exception as exc:
            raise RuntimeError(f"read password field: {exc}")
        try:
            self.accept()
        except Exception:
            pass

    def _on_cancel(self):
        self._password = None
        try:
            self.reject()
        except Exception:
            pass

    @staticmethod
    def ask(parent, message=None):
        """Prompt for the sudo password. Returns (password_or_None,
        error_or_None): error is set when the prompt itself broke (vs the
        user pressing Cancel / closing the window)."""
        try:
            dlg = SudoPasswordDialog(parent, message)
        except Exception as exc:
            return None, f"open dialog window: {exc}"
        try:
            code = dlg.exec()
        except Exception as exc:
            return None, f"{exc}"
        if code == QDialog.Accepted:
            try:
                return dlg._password, None
            except Exception as exc:
                return None, f"read password field: {exc}"
        return None, None
