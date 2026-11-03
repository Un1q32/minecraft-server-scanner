import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Dialogs
import QtQuick.Layouts
import QtQml.Models
import MC.DbViewer

ApplicationWindow {
    id: window

    width: 1440
    height: 860
    minimumWidth: 1050
    minimumHeight: 480
    visible: true
    title: "MC Server DB Viewer"
    color: pal.window
    font.family: Qt.platform.os === "windows" ? "Segoe UI" : "sans-serif"
    font.pixelSize: 13
    palette.window: pal.window
    palette.windowText: pal.text
    palette.base: pal.base
    palette.alternateBase: pal.alternateBase
    palette.text: pal.text
    palette.button: pal.button
    palette.buttonText: pal.text
    palette.highlight: pal.highlight
    palette.highlightedText: pal.highlightedText
    palette.mid: pal.mid
    property int selectedCount: 0

    // Row used as the anchor for Shift-click range selection.
    property int anchorRow: -1

    readonly property string mono: Qt.platform.os === "windows" ? "Consolas" : "monospace"
    readonly property int monoSize: 12
    readonly property int rowHeight: 24
    property real columnsWidth: 0

    // Same widths as the Python Servers tab.
    readonly property var defaultWidths: [
        170, 260, 90, 120, 75, 180, 200, 200, 165, 165, 90
    ]

    QtObject {
        id: pal
        readonly property color window: "#202020"
        readonly property color windowText: "#e0e0e0"
        readonly property color base: "#252525"
        readonly property color alternateBase: "#2b2b2b"
        readonly property color text: "#e0e0e0"
        readonly property color button: "#333333"
        readonly property color buttonText: "#e0e0e0"
        readonly property color mid: "#505050"
        readonly property color highlight: "#3b536b"
        readonly property color highlightedText: "#ffffff"
    }

    component SquareButton: Button {
        id: control
        implicitHeight: 28
        leftPadding: 9
        rightPadding: 9
        hoverEnabled: true
        font.pixelSize: 12
        contentItem: Text {
            text: control.text
            font: control.font
            color: control.enabled ? pal.text : "#777777"
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            radius: 0
            color: control.down ? "#444444" : control.hovered ? "#3b3b3b" : pal.button
            border.width: 1
            border.color: control.activeFocus ? "#b0b0b0" : "#606060"
        }
    }

    ViewerModel {
        id: viewer
    }

    TextEdit {
        id: clipboardHelper
        visible: false
        readOnly: true
        width: 1
        height: 1
    }

    // Keep the key order in sync with COLUMNS in src/model.rs.
    ListModel {
        id: headerModel
        ListElement { key: "ip_port";   display: "IP / PORT" }
        ListElement { key: "motd";      display: "MOTD" }
        ListElement { key: "players";   display: "PLAYERS" }
        ListElement { key: "version";   display: "VERSION" }
        ListElement { key: "cracked";   display: "CRACKED" }
        ListElement { key: "whitelist";   display: "WHITELIST" }
        ListElement { key: "online_names"; display: "ONLINE NAMES" }
        ListElement { key: "seen_names";  display: "SEEN NAMES" }
        ListElement { key: "first_seen";  display: "FIRST SEEN" }
        ListElement { key: "last_seen";   display: "LAST SEEN" }
        ListElement { key: "times_seen";  display: "TIMES SEEN" }
    }

    /// FileDialog gives us a url; turn it into a path Rust/Python understand.
    function urlToPath(url) {
        var s = url.toString()
        if (s.startsWith("file://")) {
            s = s.substring(7)
            if (/^\/[A-Za-z]:/.test(s))
                s = s.substring(1)
        }
        return decodeURIComponent(s)
    }

    /// TextEdit.copy() is the portable QML route to the system clipboard.
    function copyText(text) {
        clipboardHelper.text = text
        clipboardHelper.selectAll()
        clipboardHelper.copy()
    }

    function clearSelection() {
        window.anchorRow = -1
        window.selectedCount = 0
        if (table.selectionModel)
            table.selectionModel.clear()
        detailView.text = helpText
    }

    /// Click / Ctrl-click / Shift-click row selection, like a native table.
    function selectRow(row, ctrl, shift) {
        if (!table.selectionModel)
            return
        var index = table.index(row, 0)
        if (index.row < 0)
            return

        if (shift && window.anchorRow >= 0) {
            var first = Math.min(window.anchorRow, row)
            var last = Math.max(window.anchorRow, row)
            table.selectionModel.clear()
            for (var r = first; r <= last; ++r) {
                var rangeIndex = table.index(r, 0)
                if (rangeIndex.row >= 0)
                    table.selectionModel.select(rangeIndex,
                        ItemSelectionModel.Select | ItemSelectionModel.Rows)
            }
        } else if (ctrl) {
            table.selectionModel.select(index,
                ItemSelectionModel.Toggle | ItemSelectionModel.Rows)
            window.anchorRow = row
        } else {
            table.selectionModel.clear()
            table.selectionModel.select(index,
                ItemSelectionModel.Select | ItemSelectionModel.Rows)
            window.anchorRow = row
        }

        table.selectionModel.setCurrentIndex(index, ItemSelectionModel.NoUpdate)
        detailView.text = viewer.detail(row)
        window.selectedCount = window.selectedIps().length
    }

    function applySearch() {
        searchTimer.stop()
        viewer.apply(searchField.text)
        clearSelection()
    }

    function sortByColumn(column) {
        // Rust keeps the click order; later clicks are the primary sort and
        // earlier ones break ties (version then whitelist keeps version order
        // inside each whitelist group).
        viewer.toggleSort(column)
        clearSelection()
    }

    function recalculateColumnsWidth() {
        var total = 0
        for (var c = 0; c < table.columns; ++c) {
            // explicitColumnWidth knows the widths of columns that have not
            // been loaded yet (columnWidth() returns 0 for those).
            var w = table.explicitColumnWidth(c)
            if (w <= 0)
                w = table.columnWidth(c)
            total += w
        }
        if (Math.abs(total - window.columnsWidth) > 0.5)
            window.columnsWidth = total
    }

    function selectedIps() {
        if (!table.selectionModel)
            return []
        var indexes = table.selectionModel.selectedIndexes
        var seen = {}
        var ips = []
        for (var i = 0; i < indexes.length; ++i) {
            var row = indexes[i].row
            if (seen[row])
                continue
            seen[row] = true
            ips.push(viewer.ipAt(row))
        }
        return ips
    }

    function runAction(action) {
        jobDialog.validationMessage = ""
        jobDialog.actionTitle = action === "sync" ? "Database sync"
                              : action === "rescan" ? "Server rescan" : "Whitelist check"
        var error = action === "sync" ? viewer.startSync()
                  : action === "rescan" ? viewer.startRescan(window.selectedIps().join(","))
                  : viewer.startRecheck(window.selectedIps().join(","))
        jobDialog.autoShown = false
        if (error.length === 0) {
            jobShowTimer.restart()
        } else {
            jobDialog.validationMessage = error
            jobDialog.open()
        }
    }

    readonly property string helpText:
        "Select a row to see its full record.\n" +
        "\nSEARCH\n" +
        "anarchy\n" +
        "  anywhere in ip, motd, version,\n" +
        "  whitelist and player names\n" +
        "motd:\"anarchy server\"\n" +
        "  field contains text\n" +
        "ip:1.2.3.\n" +
        "  IP / port prefix\n" +
        "version~1.21   cracked=yes\n" +
        "players>=10    max<100\n" +
        "seen<7d        first>30d\n" +
        "  time windows use s/m/h/d/w\n" +
        "names:Notch\n" +
        "  player seen on the server\n" +
        "-motd:test\n" +
        "  exclude a term\n" +
        "times>3 players:0\n" +
        "  terms combine with AND"

    FileDialog {
        id: fileDialog
        title: "Open servers.db"
        nameFilters: ["SQLite databases (*.db *.sqlite *.sqlite3)", "All files (*)"]
        onAccepted: {
            if (viewer.open(urlToPath(fileDialog.selectedFile)).length === 0)
                window.applySearch()
        }
    }

    Timer {
        id: searchTimer
        interval: 300
        repeat: false
        onTriggered: window.applySearch()
    }

    // Poll the background job without blocking the UI thread.
    Timer {
        id: jobTimer
        interval: 250
        repeat: true
        running: viewer.busy
        onTriggered: viewer.pollJob()
    }

    // Only show the log for long-running jobs; a quick success stays quiet.
    Timer {
        id: jobShowTimer
        interval: 10000
        repeat: false
        onTriggered: {
            // Don't take over a log the user opened manually.
            if (viewer.busy && !jobDialog.visible) {
                jobDialog.autoShown = true
                jobDialog.open()
            }
        }
    }

    Connections {
        target: viewer
        function onJob_finishedChanged() {
            if (!viewer.job_finished)
                return
            jobShowTimer.stop()

            if (viewer.job_failed) {
                jobDialog.autoShown = false
                jobDialog.open()
            } else if (jobDialog.autoShown) {
                jobDialog.close()
                jobDialog.autoShown = false
            }
        }
    }

    Shortcut {
        sequences: ["Ctrl+O", "Cmd+O"]
        onActivated: fileDialog.open()
    }
    Shortcut {
        sequences: ["Ctrl+F", "Cmd+F"]
        onActivated: {
            searchField.forceActiveFocus()
            searchField.selectAll()
        }
    }
    Shortcut {
        sequence: "F5"
        enabled: viewer.db_path.length > 0
        onActivated: window.applySearch()
    }
    Shortcut {
        sequence: "Escape"
        onActivated: {
            if (searchField.text.length > 0) {
                searchField.text = ""
                window.applySearch()
            }
        }
    }

    Timer {
        interval: 1800
        running: Qt.application.arguments.indexOf("--export-preview") >= 0
        onTriggered: {
            var index = Qt.application.arguments.indexOf("--export-preview")
            if (Qt.application.arguments.indexOf("--preview-select-first") >= 0) {
                window.selectRow(0, false, false)
                console.log("PREVIEW_SELECTION", window.selectedCount, window.selectedIps().length)
            }
            var validationPreview = Qt.application.arguments.indexOf("--preview-error") >= 0
            if (validationPreview) {
                window.runAction("whitelist")
                console.log("PREVIEW_VALIDATION", jobDialog.validationMessage)
            }
            var surface = validationPreview ? jobDialog.contentItem : captureSurface
            surface.grabToImage(function(result) {
                result.saveToFile(Qt.application.arguments[index + 1])
                Qt.quit()
            })
        }
    }

    Component.onCompleted: {
        var initialSort = viewer.defaultSort()
        if (initialSort.length > 0)
            viewer.setSort(initialSort, viewer.defaultDesc())
        searchField.text = viewer.defaultQuery()
        if (viewer.open(viewer.defaultPath()).length === 0)
            window.applySearch()
        for (var c = 0; c < defaultWidths.length; ++c)
            table.setColumnWidth(c, defaultWidths[c])
        window.recalculateColumnsWidth()
        detailView.text = helpText
    }

    ColumnLayout {
        id: captureSurface
        anchors.fill: parent
        spacing: 0

        // ---------------------------------------------------------------- toolbar
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 42
            color: pal.window

            Rectangle {
                anchors.bottom: parent.bottom
                width: parent.width
                height: 1
                color: pal.mid
            }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 6
                anchors.rightMargin: 6
                spacing: 6

                SquareButton {
                    text: "Open DB…"
                    onClicked: fileDialog.open()
                }

                TextField {
                    id: searchField
                    implicitHeight: 28
                    leftPadding: 6; rightPadding: 6
                    color: pal.text
                    placeholderTextColor: "#aaaaaa"
                    background: Rectangle {
                        radius: 0; color: pal.base; border.width: 1
                        border.color: searchField.activeFocus ? "#8b8b8b" : pal.mid
                    }
                    Layout.fillWidth: true
                    placeholderText: "Search…  motd:anarchy players>=10 seen<7d"
                    selectByMouse: true
                    onTextChanged: searchTimer.restart()
                    onAccepted: window.applySearch()

                    ToolTip.visible: hovered && text.length === 0
                    ToolTip.text: "Bare words match ip, motd, version, whitelist and player names."
                }

                SquareButton {
                    text: "Copy IP(s)"
                    enabled: viewer.db_path.length > 0
                    ToolTip.visible: hovered
                    ToolTip.text: "Copy the selected IP:PORT rows, one per line"
                    onClicked: {
                        var ips = window.selectedIps()
                        if (ips.length === 0) {
                            viewer.note("Select one or more server rows first.")
                        } else {
                            window.copyText(ips.join("\n"))
                            viewer.note("Copied " + ips.length + " IP(s).")
                        }
                    }
                }

                SquareButton {
                    text: viewer.busy ? "Working…" : "Rescan"
                    enabled: !viewer.busy && viewer.db_path.length > 0
                    onClicked: window.runAction("rescan")
                }

                SquareButton {
                    text: viewer.busy ? "Working…" : "Sync DB"
                    enabled: !viewer.busy && viewer.db_path.length > 0
                    onClicked: window.runAction("sync")
                }

                SquareButton {
                    text: viewer.busy ? "Working…" : "Recheck whitelist"
                    enabled: !viewer.busy && viewer.db_path.length > 0
                    onClicked: window.runAction("whitelist")
                }
            }
        }

        // ------------------------------------------------------------------- body
        SplitView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            orientation: Qt.Horizontal

            Item {
                SplitView.fillWidth: true
                SplitView.minimumWidth: 500

                // Native tables keep their base colour below the last row too.
                Rectangle {
                    anchors.fill: parent
                    color: pal.base
                }

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 0

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 26
                        Layout.maximumHeight: 26
                        spacing: 0

                    HorizontalHeaderView {
                        id: header
                        Layout.fillWidth: true
                        Layout.preferredHeight: 26
                        clip: true
                        syncView: table
                        model: headerModel
                        resizableColumns: true
                        pointerNavigationEnabled: false

                        delegate: Rectangle {
                            required property string key
                            required property string display

                            implicitWidth: 100
                            implicitHeight: 26
                            color: pal.button

                            Rectangle {
                                anchors.right: parent.right
                                width: 1
                                height: parent.height
                                color: pal.mid
                                opacity: 0.55
                            }

                            Text {
                                anchors.left: parent.left
                                anchors.leftMargin: 6
                                anchors.right: parent.right
                                anchors.rightMargin: 6
                                anchors.verticalCenter: parent.verticalCenter
                                text: display
                                    + (viewer.sort_column === key
                                       ? (viewer.sort_desc ? " ▼" : " ▲") : "")
                                color: pal.buttonText
                                opacity: viewer.sort_column === key ? 1.0 : 0.65
                                font.pixelSize: 11
                                font.bold: true
                                font.letterSpacing: 0.5
                                elide: Text.ElideRight
                            }

                            // Leave a margin at each edge so Qt's native
                            // header-resize handles remain reachable.
                            MouseArea {
                                anchors.fill: parent
                                anchors.leftMargin: 7
                                anchors.rightMargin: 7
                                acceptedButtons: Qt.LeftButton
                                cursorShape: Qt.PointingHandCursor
                                onClicked: window.sortByColumn(key)
                            }
                        }
                    }

                        Item {
                            Layout.preferredWidth: tableVBar.visible ? 16 : 0
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        spacing: 0

                    TableView {
                        id: table
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true

                        model: viewer
                        selectionModel: ItemSelectionModel { model: viewer }
                        selectionBehavior: TableView.SelectRows
                        selectionMode: TableView.ExtendedSelection
                        pointerNavigationEnabled: false
                        resizableColumns: true
                        contentWidth: Math.max(width, window.columnsWidth)

                        rowHeightProvider: function (row) { return window.rowHeight }

                        delegate: Rectangle {
                            required property int row
                            required property int column
                            required property bool selected
                            required property string display

                            implicitWidth: 100
                            implicitHeight: window.rowHeight
                            // Do not use palette.alternateBase here: on macOS it can
                            // be pure white even in dark mode, leaving white text on a
                            // white row. Tint the base with the text colour instead, so
                            // the stripe always has the correct contrast.
                            color: selected
                                   ? pal.highlight
                                   : (row % 2 === 0
                                      ? "transparent"
                                      : Qt.rgba(pal.text.r, pal.text.g,
                                                pal.text.b, 0.055))

                            Text {
                                anchors.fill: parent
                                anchors.leftMargin: 6
                                anchors.rightMargin: 6
                                verticalAlignment: Text.AlignVCenter
                                text: display
                                textFormat: Text.PlainText
                                color: selected ? pal.highlightedText : pal.text
                                font.family: window.mono
                                font.pixelSize: window.monoSize
                                elide: Text.ElideRight
                            }

                            MouseArea {
                                anchors.fill: parent
                                acceptedButtons: Qt.LeftButton
                                cursorShape: Qt.PointingHandCursor
                                onClicked: function (mouse) {
                                    window.selectRow(
                                        row,
                                        (mouse.modifiers & Qt.ControlModifier) !== 0,
                                        (mouse.modifiers & Qt.ShiftModifier) !== 0)
                                }
                            }
                        }

                        onLayoutChanged: window.recalculateColumnsWidth()

                        onCurrentRowChanged: {
                            if (currentRow >= 0)
                                detailView.text = viewer.detail(currentRow)
                        }
                    }

                        Item {
                            id: tableVBar
                            Layout.preferredWidth: 16
                            Layout.fillHeight: true
                            visible: table.contentHeight > table.height

                            Rectangle {
                                anchors.fill: parent
                                color: pal.button
                            }
                            Rectangle {
                                anchors.left: parent.left
                                width: 1
                                height: parent.height
                                color: pal.mid
                            }

                            Rectangle {
                                id: tableVBarThumb
                                width: 8
                                height: Math.max(24,
                                    tableVBar.height * table.height
                                    / Math.max(1, table.contentHeight))
                                radius: 0
                                x: (tableVBar.width - width) / 2
                                y: {
                                    var travel = table.contentHeight - table.height
                                    var track = tableVBar.height - height
                                    return travel > 0 && track > 0
                                        ? track * table.contentY / travel : 0
                                }
                                color: vbarDrag.containsMouse || vbarDrag.pressed
                                       ? pal.highlight : pal.text
                                opacity: vbarDrag.containsMouse || vbarDrag.pressed
                                         ? 1.0 : 0.45
                            }

                            MouseArea {
                                id: vbarDrag
                                anchors.fill: parent
                                hoverEnabled: true

                                property real pressOffset: 0

                                function scrollTo(mouseY) {
                                    var travel = table.contentHeight - table.height
                                    var track = tableVBar.height - tableVBarThumb.height
                                    if (travel <= 0 || track <= 0)
                                        return
                                    var thumbY = Math.max(0,
                                        Math.min(track, mouseY - pressOffset))
                                    table.contentY = thumbY / track * travel
                                }

                                onPressed: function (mouse) {
                                    if (mouse.y >= tableVBarThumb.y
                                            && mouse.y <= tableVBarThumb.y + tableVBarThumb.height) {
                                        pressOffset = mouse.y - tableVBarThumb.y
                                    } else {
                                        pressOffset = tableVBarThumb.height / 2
                                        scrollTo(mouse.y)
                                    }
                                }
                                onPositionChanged: function (mouse) {
                                    if (pressed)
                                        scrollTo(mouse.y)
                                }
                            }
                        }
                    }

                    // Horizontal bar lives in its own strip below the table,
                    // with the side column reserved for the vertical bar.
                    RowLayout {
                        Layout.fillWidth: true
                        Layout.preferredHeight: tableHBar.visible ? 16 : 0
                        Layout.maximumHeight: 16
                        spacing: 0

                        Item {
                            id: tableHBar
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            visible: table.contentWidth > table.width

                            Rectangle {
                                anchors.fill: parent
                                color: pal.button
                            }
                            Rectangle {
                                anchors.top: parent.top
                                width: parent.width
                                height: 1
                                color: pal.mid
                            }

                            Rectangle {
                                id: tableHBarThumb
                                height: 8
                                width: Math.max(30,
                                    (tableHBar.width - 4) * table.width
                                    / Math.max(1, table.contentWidth))
                                radius: 0
                                y: (tableHBar.height - height) / 2
                                x: {
                                    var travel = table.contentWidth - table.width
                                    var track = tableHBar.width - 4 - width
                                    return 2 + (travel > 0 && track > 0
                                        ? track * table.contentX / travel : 0)
                                }
                                color: hbarDrag.containsMouse || hbarDrag.pressed
                                       ? pal.highlight : pal.text
                                opacity: hbarDrag.containsMouse || hbarDrag.pressed
                                         ? 1.0 : 0.45
                            }

                            MouseArea {
                                id: hbarDrag
                                anchors.fill: parent
                                hoverEnabled: true

                                property real pressOffset: 0

                                function scrollTo(mouseX) {
                                    var travel = table.contentWidth - table.width
                                    var track = tableHBar.width - 4 - tableHBarThumb.width
                                    if (travel <= 0 || track <= 0)
                                        return
                                    var thumbX = Math.max(0,
                                        Math.min(track, mouseX - 2 - pressOffset))
                                    table.contentX = thumbX / track * travel
                                }

                                onPressed: function (mouse) {
                                    if (mouse.x >= tableHBarThumb.x
                                            && mouse.x <= tableHBarThumb.x + tableHBarThumb.width) {
                                        pressOffset = mouse.x - tableHBarThumb.x
                                    } else {
                                        pressOffset = tableHBarThumb.width / 2
                                        scrollTo(mouse.x)
                                    }
                                }
                                onPositionChanged: function (mouse) {
                                    if (pressed)
                                        scrollTo(mouse.x)
                                }
                            }
                        }

                        Item {
                            Layout.preferredWidth: tableVBar.visible ? 16 : 0
                        }
                    }
                }

                // Empty state / hint (outside the flickable so it stays put).
                Text {
                    anchors.centerIn: parent
                    width: Math.min(parent.width - 80, 720)
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                    visible: viewer.shown === 0
                    z: 2
                    color: pal.text
                    opacity: 0.55
                    font.pixelSize: 13
                    text: viewer.db_path.length === 0
                          ? "Open a servers.db to get started (Ctrl+O)."
                          : "No rows match this query."
                }
            }

            Rectangle {
                SplitView.preferredWidth: 360
                SplitView.minimumWidth: 240
                color: pal.window

                Rectangle {
                    anchors.left: parent.left
                    width: 1
                    height: parent.height
                    color: pal.mid
                }

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 10
                    spacing: 8

                    RowLayout {
                        Layout.fillWidth: true

                        Text {
                            Layout.fillWidth: true
                            text: "DETAIL"
                            color: pal.windowText
                            opacity: 0.6
                            font.pixelSize: 11
                            font.bold: true
                            font.letterSpacing: 1
                        }

                        SquareButton {
                            text: "Notes"
                            flat: true
                            enabled: viewer.db_path.length > 0
                                     && table.currentRow >= 0
                            onClicked: {
                                var row = table.currentRow
                                if (row < 0) {
                                    viewer.note("Select a server row first.")
                                    return
                                }
                                notesDialog.row = row
                                notesDialog.refresh()
                                notesDialog.open()
                            }
                        }

                        SquareButton {
                            text: "Log"
                            flat: true
                            enabled: viewer.job_log.length > 0
                            onClicked: {
                                jobDialog.validationMessage = ""
                                jobDialog.actionTitle = "Activity log"
                                jobDialog.autoShown = false
                                jobDialog.open()
                            }
                        }
                    }

                    ScrollView {
                        id: detailScroll
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true

                        TextArea {
                            id: detailView
                            color: pal.text
                            selectionColor: pal.highlight
                            selectedTextColor: pal.highlightedText
                            background: Rectangle { color: pal.base; radius: 0; border.color: pal.mid }
                            width: detailScroll.availableWidth
                            readOnly: true
                            selectByMouse: true
                            textFormat: TextEdit.PlainText
                            wrapMode: TextEdit.WrapAtWordBoundaryOrAnywhere
                            font.family: window.mono
                            font.pixelSize: 12
                            padding: 8
                        }
                    }
                }
            }
        }

        // --------------------------------------------------------------- status
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 26
            color: pal.window

            Rectangle {
                anchors.top: parent.top
                width: parent.width
                height: 1
                color: pal.mid
            }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 6
                anchors.rightMargin: 6
                spacing: 16

                Text {
                    text: window.selectedCount + " selected  |  " + viewer.status
                    color: pal.windowText
                    opacity: 0.8
                    font.bold: viewer.busy
                    font.pixelSize: 11
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                }

                Text {
                    text: viewer.db_path
                    color: pal.windowText
                    opacity: 0.5
                    font.pixelSize: 11
                    elide: Text.ElideMiddle
                    Layout.maximumWidth: 520
                }
            }
        }
    }

    // Dropping a database file opens it; on top so it sees every drag.
    DropArea {
        anchors.fill: parent
        z: 100
        onDropped: function (drop) {
            if (drop.hasUrls && drop.urls.length > 0) {
                if (viewer.open(urlToPath(drop.urls[0])).length === 0)
                    window.applySearch()
            }
        }
    }

    Dialog {
        id: jobDialog
        title: actionTitle
        property string actionTitle: "Activity log"
        property string validationMessage: ""
        parent: Overlay.overlay
        anchors.centerIn: parent
        background: Rectangle { color: pal.window; radius: 0; border.color: pal.mid }
        property bool autoShown: false
        width: Math.min(window.width - 48, 880)
        height: Math.min(window.height - 48, 500)
        modal: false
        footer: Item {
            implicitHeight: 40
            SquareButton {
                anchors.right: parent.right; anchors.rightMargin: 8
                anchors.verticalCenter: parent.verticalCenter
                text: "Close"
                onClicked: jobDialog.close()
            }
        }

        contentItem: ScrollView {
            id: jobScroll
            clip: true

            TextArea {
                id: jobText
                width: jobScroll.availableWidth
                text: jobDialog.validationMessage.length > 0 ? jobDialog.validationMessage : viewer.job_log
                color: pal.text
                selectionColor: pal.highlight
                selectedTextColor: pal.highlightedText
                background: Rectangle { color: pal.base; radius: 0; border.color: pal.mid }
                readOnly: true
                selectByMouse: true
                textFormat: TextEdit.PlainText
                wrapMode: TextEdit.WrapAtWordBoundaryOrAnywhere
                font.family: window.mono
                font.pixelSize: 12
                padding: 8

                // Replacing the bound text resets the cursor to position 0,
                // which makes the view jump to the top. Keep the cursor at
                // the end so new mcscan.py output stays visible at the
                // bottom (whitelist rechecks can append thousands of lines).
                onTextChanged: cursorPosition = length
            }
        }
    }

    ListModel {
        id: notesModel
    }

    Dialog {
        id: notesDialog
        property int row: -1
        property string notesJson: "[]"
        title: "Notes — " + (row >= 0 ? viewer.ipAt(row) : "")
        parent: Overlay.overlay
        anchors.centerIn: parent
        modal: true
        background: Rectangle { color: pal.window; radius: 0; border.color: pal.mid }
        width: Math.min(window.width - 48, 720)
        height: Math.min(window.height - 48, 560)
        padding: 10

        function refresh() {
            notesJson = viewer.notesFor(row)
            notesModel.clear()
            var data = []
            try { data = JSON.parse(notesJson) } catch (e) { data = [] }
            for (var i = 0; i < data.length; ++i) {
                notesModel.append({
                    noteId: data[i].id,
                    createdText: data[i].created,
                    noteText: data[i].text
                })
            }
        }

        function addNote() {
            var error = viewer.addNote(row, noteInput.text)
            if (error.length > 0) {
                viewer.note(error)
                return
            }
            noteInput.text = ""
            refresh()
            detailView.text = viewer.detail(row)
            viewer.note("Note added.")
        }

        function removeNote(noteId) {
            var error = viewer.deleteNote(row, noteId)
            if (error.length > 0) {
                viewer.note(error)
                return
            }
            refresh()
            detailView.text = viewer.detail(row)
            viewer.note("Note deleted for the next sync.")
        }

        onOpened: refresh()

        contentItem: ColumnLayout {
            spacing: 8

            Text {
                visible: notesModel.count === 0
                text: "No notes yet."
                color: pal.text
                opacity: 0.6
            }

            ListView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                model: notesModel
                spacing: 2

                delegate: Rectangle {
                    width: ListView.view.width
                    implicitHeight: noteRow.implicitHeight + 8
                    color: index % 2 === 0 ? "transparent" : Qt.rgba(
                               pal.text.r, pal.text.g, pal.text.b, 0.04)

                    RowLayout {
                        id: noteRow
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.leftMargin: 4
                        anchors.rightMargin: 4
                        spacing: 8

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Text {
                                text: createdText
                                color: pal.text
                                opacity: 0.55
                                font.pixelSize: 11
                            }

                            Text {
                                Layout.fillWidth: true
                                text: noteText
                                color: pal.text
                                textFormat: Text.PlainText
                                wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                            }
                        }

                        SquareButton {
                            text: "Delete"
                            flat: true
                            onClicked: notesDialog.removeNote(noteId)
                        }
                    }
                }
            }

            TextArea {
                id: noteInput
                Layout.fillWidth: true
                Layout.preferredHeight: 64
                color: pal.text
                placeholderText: "Write a note (notes cannot be edited once saved)…"
                placeholderTextColor: "#aaaaaa"
                selectByMouse: true
                wrapMode: TextEdit.Wrap
                background: Rectangle {
                    color: pal.base
                    border.color: pal.mid
                    border.width: 1
                }
            }

            RowLayout {
                Layout.fillWidth: true

                SquareButton {
                    text: "Add Note"
                    enabled: noteInput.text.trim().length > 0
                    onClicked: notesDialog.addNote()
                }

                Item { Layout.fillWidth: true }
            }
        }

        footer: Item {
            implicitHeight: 40
            SquareButton {
                anchors.right: parent.right; anchors.rightMargin: 8
                anchors.verticalCenter: parent.verticalCenter
                text: "Close"
                onClicked: notesDialog.close()
            }
        }
    }
}
