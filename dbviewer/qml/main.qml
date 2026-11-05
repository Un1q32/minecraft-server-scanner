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

    // Sighting / player history for the selected row.  Rust sends JSON; the
    // canvases below parse it once per selection and repaint on resize.
    property bool historyLoaded: false
    property var historyData: ({ points: [], players: [] })
    property real chartViewStart: 0
    property real chartViewEnd: 0
    property bool chartZoomed: false
    readonly property var chartColors: [
        "#6fa8dc", "#93c47d", "#e6b85c", "#e07b8f", "#b4a7d6",
        "#76a5af", "#f0a35e", "#c3d36c", "#d98cc4", "#8fb8e8"
    ]

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
        clearHistory()
    }

    /// Load and repaint the history graphs for a row (-1 clears them).
    function loadHistory(row) {
        if (row < 0) {
            clearHistory()
            return
        }
        var data = { points: [], players: [] }
        try {
            var parsed = JSON.parse(viewer.history(row))
            if (parsed && parsed.points)
                data = parsed
        } catch (error) {
            data = { points: [], players: [] }
        }
        if (!data.players)
            data.players = []
        historyData = data
        historyLoaded = true
        resetChartView()
    }

    function clearHistory() {
        historyLoaded = false
        historyData = ({ points: [], players: [] })
        chartViewStart = 0
        chartViewEnd = 0
        chartZoomed = false
        serverChart.requestPaint()
        playerChart.requestPaint()
    }

    /// Canvas wants a CSS colour string, not a QML color variant.
    function cssColor(c) {
        var alpha = c.a === undefined ? 1 : c.a
        return "rgba(" + Math.round(c.r * 255) + "," +
               Math.round(c.g * 255) + "," + Math.round(c.b * 255) + "," +
               alpha + ")"
    }

    /// Local 12-hour timestamp used by the charts and their axis labels.
    function chartTime(epoch) {
        if (!epoch || epoch <= 0)
            return "-"
        var d = new Date(epoch * 1000)
        var hours = d.getHours()
        var suffix = hours >= 12 ? "PM" : "AM"
        hours = hours % 12
        if (hours === 0)
            hours = 12
        var minutes = d.getMinutes()
        return (d.getMonth() + 1) + "/" + d.getDate() + " " +
               hours + ":" + (minutes < 10 ? "0" : "") + minutes + " " + suffix
    }

    function historyRange(points, players) {
        var lo = 0
        var hi = 0
        for (var i = 0; i < points.length; ++i) {
            var t = Number(points[i].t) || 0
            if (t <= 0)
                continue
            if (!lo || t < lo)
                lo = t
            if (t > hi)
                hi = t
        }
        if (!lo) {
            for (var p = 0; p < players.length; ++p) {
                var times = players[p].times || []
                for (var k = 0; k < times.length; ++k) {
                    var pt = Number(times[k]) || 0
                    if (pt <= 0)
                        continue
                    if (!lo || pt < lo)
                        lo = pt
                    if (pt > hi)
                        hi = pt
                }
            }
        }
        if (!lo)
            return [0, 0]
        if (hi <= lo)
            hi = lo + 3600
        return [lo, hi]
    }

    function chartFullRange() {
        return historyRange(historyData.points || [], historyData.players || [])
    }

    function chartViewRange() {
        var full = chartFullRange()
        var start = chartViewStart
        var end = chartViewEnd
        if (!start || !end || end <= start)
            return full
        if (start < full[0])
            start = full[0]
        if (end > full[1])
            end = full[1]
        if (end <= start)
            return full
        return [start, end]
    }

    function setChartView(start, end) {
        var full = chartFullRange()
        if (!full[0] && !full[1])
            return
        var span = Math.max(0.001, end - start)
        var fullSpan = Math.max(0.001, full[1] - full[0])
        if (span >= fullSpan * 0.999) {
            chartViewStart = full[0]
            chartViewEnd = full[1]
            chartZoomed = false
        } else {
            if (start < full[0]) {
                start = full[0]
                end = start + span
            }
            if (end > full[1]) {
                end = full[1]
                start = end - span
            }
            if (start < full[0]) {
                start = full[0]
                end = start + span
            }
            chartViewStart = start
            chartViewEnd = end
            chartZoomed = true
        }
        serverChart.requestPaint()
        playerChart.requestPaint()
    }

    function resetChartView() {
        var full = chartFullRange()
        chartViewStart = full[0]
        chartViewEnd = full[1]
        chartZoomed = false
        serverChart.requestPaint()
        playerChart.requestPaint()
    }

    function zoomChartAt(deltaY, x, width, left, right) {
        var full = chartFullRange()
        if ((!full[0] && !full[1]) || !deltaY)
            return
        var view = chartViewRange()
        var plot = Math.max(1, width - left - right)
        var fraction = Math.max(0, Math.min(1, (x - left) / plot))
        var span = Math.max(0.001, view[1] - view[0])
        var fullSpan = Math.max(0.001, full[1] - full[0])
        var steps = Math.max(0.1, Math.min(4, Math.abs(deltaY) / 120))
        var factor = deltaY < 0 ? Math.pow(0.5, steps) : Math.pow(2.0, steps)
        var minSpan = Math.min(fullSpan, 0.5)
        var newSpan = span * factor
        newSpan = Math.max(minSpan, Math.min(fullSpan, newSpan))
        var anchor = view[0] + fraction * span
        var newStart = anchor - fraction * newSpan
        setChartView(newStart, newStart + newSpan)
    }

    function panChartPixels(dx, width, left, right) {
        if (!chartZoomed)
            return
        var view = chartViewRange()
        var span = Math.max(0.001, view[1] - view[0])
        var plot = Math.max(1, width - left - right)
        var delta = -dx / plot * span
        setChartView(view[0] + delta, view[1] + delta)
    }

    function paintServerChart() {
        var ctx = serverChart.getContext("2d")
        var w = serverChart.width
        var h = serverChart.height
        ctx.clearRect(0, 0, w, h)
        ctx.fillStyle = cssColor(pal.base)
        ctx.fillRect(0, 0, w, h)
        ctx.strokeStyle = cssColor(pal.mid)
        ctx.lineWidth = 1
        ctx.strokeRect(0.5, 0.5, w - 1, h - 1)

        var points = historyLoaded ? (historyData.points || []) : []
        if (!points.length) {
            ctx.fillStyle = cssColor(pal.text)
            ctx.globalAlpha = 0.65
            ctx.font = "12px " + window.mono
            ctx.textAlign = "left"
            ctx.textBaseline = "middle"
            ctx.fillText(historyLoaded
                         ? "No sighting history recorded for this server."
                         : "Select a server to see its sighting history.", 10, h / 2)
            ctx.globalAlpha = 1
            return
        }

        var left = 40
        var right = 8
        var top = 20
        var bottom = 22
        var pw = Math.max(1, w - left - right)
        var ph = Math.max(1, h - top - bottom)
        var range = chartFullRange()
        var view = chartViewRange()
        var t0 = view[0]
        var t1 = view[1]
        var span = Math.max(1, t1 - t0)
        var globalPeak = 1
        var globalCounted = 0
        for (var gi = 0; gi < points.length; ++gi) {
            if (points[gi].p !== null && points[gi].p !== undefined) {
                globalPeak = Math.max(globalPeak, Number(points[gi].p) || 0)
                globalCounted += 1
            }
        }
        if (!globalCounted) {
            for (var gm = 0; gm < points.length; ++gm) {
                if (points[gm].m !== null && points[gm].m !== undefined)
                    globalPeak = Math.max(globalPeak, Number(points[gm].m) || 0)
            }
        }
        var peak = 1
        var counted = 0
        var visible = 0
        for (var i = 0; i < points.length; ++i) {
            var at = Number(points[i].t) || 0
            if (at < t0 || at > t1)
                continue
            visible += 1
            var value = points[i].p
            if (value !== null && value !== undefined) {
                peak = Math.max(peak, Number(value) || 0)
                counted += 1
            }
        }
        if (!counted) {
            for (var c = 0; c < points.length; ++c) {
                var mt = Number(points[c].t) || 0
                if (mt < t0 || mt > t1)
                    continue
                var maximum = points[c].m
                if (maximum !== null && maximum !== undefined)
                    peak = Math.max(peak, Number(maximum) || 0)
            }
        }
        if (!counted)
            peak = Math.max(peak, globalPeak)

        ctx.font = "11px " + window.mono
        ctx.textBaseline = "middle"

        // Horizontal grid and the player-count scale.
        for (var g = 0; g <= 2; ++g) {
            var valueAt = Math.round(peak * g / 2)
            var y = top + ph - ph * g / 2
            ctx.strokeStyle = cssColor(pal.mid)
            ctx.globalAlpha = g === 0 ? 0.55 : 0.25
            ctx.beginPath()
            ctx.moveTo(left, y + 0.5)
            ctx.lineTo(left + pw, y + 0.5)
            ctx.stroke()
            ctx.globalAlpha = 0.7
            ctx.fillStyle = cssColor(pal.text)
            ctx.textAlign = "right"
            ctx.fillText(String(valueAt), left - 5, y)
        }
        ctx.globalAlpha = 1

        // Keep the plot contents inside the viewport while panning.
        ctx.save()
        ctx.beginPath()
        ctx.rect(left, top, pw, ph + 8)
        ctx.clip()

        // Player count over time; older/backfilled rows have no count.
        var drawing = false
        ctx.strokeStyle = chartColors[0]
        ctx.lineWidth = 1.5
        ctx.beginPath()
        for (var p = 0; p < points.length; ++p) {
            var v = points[p].p
            if (v === null || v === undefined) {
                if (drawing) {
                    ctx.stroke()
                    drawing = false
                    ctx.beginPath()
                }
                continue
            }
            var x = left + ((Number(points[p].t) || t0) - t0) / span * pw
            var py = top + ph - Math.min(1, (Number(v) || 0) / peak) * ph
            if (!drawing) {
                ctx.moveTo(x, py)
                drawing = true
            } else {
                ctx.lineTo(x, py)
            }
        }
        if (drawing)
            ctx.stroke()

        // Every sighting is a dot and a tick.  Drawing all of them matters
        // when zoomed in: the whole point is to see the dense rescans.
        ctx.fillStyle = chartColors[0]
        for (var d = 0; d < points.length; ++d) {
            var dv = points[d].p
            if (dv === null || dv === undefined)
                continue
            var dx = left + ((Number(points[d].t) || t0) - t0) / span * pw
            var dy = top + ph - Math.min(1, (Number(dv) || 0) / peak) * ph
            ctx.beginPath()
            ctx.arc(dx, dy, 1.6, 0, Math.PI * 2)
            ctx.fill()
        }

        // Sighting ticks: every point is an observation of the server.
        ctx.strokeStyle = cssColor(pal.highlight)
        ctx.globalAlpha = 0.8
        ctx.lineWidth = 1
        for (var ts = 0; ts < points.length; ++ts) {
            var tx = left + ((Number(points[ts].t) || t0) - t0) / span * pw
            ctx.beginPath()
            ctx.moveTo(tx + 0.5, top + ph + 2)
            ctx.lineTo(tx + 0.5, top + ph + 6)
            ctx.stroke()
        }
        ctx.globalAlpha = 1
        ctx.restore()

        // Labels.
        ctx.fillStyle = cssColor(pal.text)
        ctx.globalAlpha = 0.85
        ctx.textAlign = "left"
        ctx.fillText("SIGHTINGS " + points.length + "  •  PEAK " + globalPeak +
                     (chartZoomed ? "  •  ZOOMED" : ""), left, 10)
        ctx.globalAlpha = 0.65
        ctx.textAlign = "left"
        ctx.fillText(chartTime(t0), left, h - 9)
        ctx.textAlign = "right"
        ctx.fillText(chartTime(t1), left + pw, h - 9)
        ctx.globalAlpha = 1
        if (!visible) {
            ctx.fillStyle = cssColor(pal.text)
            ctx.globalAlpha = 0.6
            ctx.textAlign = "center"
            ctx.fillText("No sightings in this zoom window",
                         left + pw / 2, top + ph / 2)
            ctx.globalAlpha = 1
        } else if (!counted) {
            ctx.fillStyle = cssColor(pal.text)
            ctx.globalAlpha = 0.6
            ctx.textAlign = "center"
            ctx.fillText("No player counts recorded for these sightings",
                         left + pw / 2, top + ph / 2)
            ctx.globalAlpha = 1
        }
    }

    function paintPlayerChart() {
        var ctx = playerChart.getContext("2d")
        var w = playerChart.width
        var h = playerChart.height
        ctx.clearRect(0, 0, w, h)
        ctx.fillStyle = cssColor(pal.base)
        ctx.fillRect(0, 0, w, h)
        ctx.strokeStyle = cssColor(pal.mid)
        ctx.lineWidth = 1
        ctx.strokeRect(0.5, 0.5, w - 1, h - 1)

        var players = historyLoaded ? (historyData.players || []) : []
        if (!players.length) {
            ctx.fillStyle = cssColor(pal.text)
            ctx.globalAlpha = 0.65
            ctx.font = "12px " + window.mono
            ctx.textAlign = "left"
            ctx.textBaseline = "middle"
            ctx.fillText("No player samples recorded for this server.", 10, h / 2)
            ctx.globalAlpha = 1
            return
        }

        // Show the most frequently sampled players; the rest are summarised.
        var sorted = players.slice().sort(function (a, b) {
            var at = (a.times || []).length
            var bt = (b.times || []).length
            return bt - at || String(a.name).localeCompare(String(b.name))
        })
        var left = 92
        var right = 8
        var top = 18
        var bottom = 8
        var maxRows = Math.max(1, Math.floor((h - top - bottom) / 12))
        var shown = Math.min(sorted.length, maxRows)
        var overflow = sorted.length - shown
        if (overflow > 0)
            shown = Math.max(1, shown - 1)
        var rowHeight = (h - top - bottom) / Math.max(1, shown + (overflow > 0 ? 1 : 0))
        var pw = Math.max(1, w - left - right)
        var range = chartViewRange()
        var t0 = range[0]
        var t1 = range[1]
        var span = Math.max(1, t1 - t0)

        ctx.font = "11px " + window.mono
        ctx.textBaseline = "middle"

        for (var r = 0; r < shown; ++r) {
            var player = sorted[r]
            var rowY = top + rowHeight * r
            var centerY = rowY + rowHeight / 2
            var color = chartColors[r % chartColors.length]

            ctx.strokeStyle = cssColor(pal.mid)
            ctx.globalAlpha = 0.22
            ctx.beginPath()
            ctx.moveTo(left, centerY + 0.5)
            ctx.lineTo(left + pw, centerY + 0.5)
            ctx.stroke()
            ctx.globalAlpha = 1

            var name = String(player.name || "")
            if (name.length > 13)
                name = name.substring(0, 12) + "…"
            ctx.fillStyle = cssColor(pal.text)
            ctx.globalAlpha = 0.9
            ctx.textAlign = "left"
            ctx.fillText(name, 6, centerY)
            ctx.globalAlpha = 1

            ctx.fillStyle = color
            var times = player.times || []
            ctx.save()
            ctx.beginPath()
            ctx.rect(left, top, pw, h - top - bottom)
            ctx.clip()
            for (var k = 0; k < times.length; ++k) {
                var eventTime = Number(times[k]) || 0
                var x = left + ((eventTime || t0) - t0) / span * pw
                ctx.beginPath()
                ctx.arc(x, centerY, 1.7, 0, Math.PI * 2)
                ctx.fill()
            }
            ctx.restore()
        }

        if (overflow > 0) {
            ctx.fillStyle = cssColor(pal.text)
            ctx.globalAlpha = 0.6
            ctx.textAlign = "left"
            ctx.fillText("+" + overflow + " more player(s)", 6,
                         top + rowHeight * shown + rowHeight / 2)
            ctx.globalAlpha = 1
        }

        ctx.fillStyle = cssColor(pal.text)
        ctx.globalAlpha = 0.85
        ctx.textAlign = "left"
        ctx.fillText("PLAYER ACTIVITY  •  " + players.length + " SEEN  •  " +
                     chartTime(t0) + " – " + chartTime(t1) +
                     (chartZoomed ? "  •  ZOOMED" : ""), 6, 9)
        ctx.globalAlpha = 1
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
        window.loadHistory(row)
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
                            if (currentRow >= 0) {
                                detailView.text = viewer.detail(currentRow)
                                window.loadHistory(currentRow)
                            } else {
                                window.clearHistory()
                            }
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
                            text: window.historyLoaded
                                  ? "DETAIL · WHEEL ZOOM · DRAG PAN"
                                  : "DETAIL"
                            color: pal.windowText
                            opacity: 0.6
                            font.pixelSize: 11
                            font.bold: true
                            font.letterSpacing: 1
                            elide: Text.ElideRight
                        }

                        SquareButton {
                            text: "Reset zoom"
                            flat: true
                            visible: window.historyLoaded && window.chartZoomed
                            onClicked: window.resetChartView()
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

                    Canvas {
                        id: serverChart
                        visible: window.historyLoaded
                        Layout.fillWidth: true
                        Layout.preferredHeight: visible ? 150 : 0
                        onPaint: window.paintServerChart()
                        onWidthChanged: requestPaint()
                        onHeightChanged: requestPaint()

                        MouseArea {
                            anchors.fill: parent
                            acceptedButtons: Qt.LeftButton
                            hoverEnabled: true
                            cursorShape: pressed
                                         ? Qt.ClosedHandCursor
                                         : Qt.OpenHandCursor
                            property real lastX: 0

                            onPressed: lastX = mouseX
                            onPositionChanged: {
                                if (!pressed)
                                    return
                                var dx = mouseX - lastX
                                lastX = mouseX
                                window.panChartPixels(dx, parent.width, 40, 8)
                            }
                            onWheel: function (wheel) {
                                window.zoomChartAt(wheel.angleDelta.y,
                                                   wheel.x, parent.width, 40, 8)
                                wheel.accepted = true
                            }
                            onDoubleClicked: window.resetChartView()
                        }
                    }

                    Canvas {
                        id: playerChart
                        visible: window.historyLoaded
                                 && (window.historyData.players || []).length > 0
                        Layout.fillWidth: true
                        Layout.preferredHeight: visible ? 165 : 0
                        onPaint: window.paintPlayerChart()
                        onWidthChanged: requestPaint()
                        onHeightChanged: requestPaint()

                        MouseArea {
                            anchors.fill: parent
                            acceptedButtons: Qt.LeftButton
                            hoverEnabled: true
                            cursorShape: pressed
                                         ? Qt.ClosedHandCursor
                                         : Qt.OpenHandCursor
                            property real lastX: 0

                            onPressed: lastX = mouseX
                            onPositionChanged: {
                                if (!pressed)
                                    return
                                var dx = mouseX - lastX
                                lastX = mouseX
                                window.panChartPixels(dx, parent.width, 92, 8)
                            }
                            onWheel: function (wheel) {
                                window.zoomChartAt(wheel.angleDelta.y,
                                                   wheel.x, parent.width, 92, 8)
                                wheel.accepted = true
                            }
                            onDoubleClicked: window.resetChartView()
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
