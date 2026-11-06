package com.mcdbbrowser;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Supplier;
import com.mcdbbrowser.ServerDatabase.Query;
import com.mcdbbrowser.ServerDatabase.QueryResult;
import net.minecraft.ChatFormatting;
import net.minecraft.client.gui.Font;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.components.ObjectSelectionList;
import net.minecraft.client.gui.components.Tooltip;
import net.minecraft.client.gui.components.events.GuiEventListener;
import net.minecraft.client.gui.screens.ConnectScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.input.KeyEvent;
import net.minecraft.client.input.MouseButtonEvent;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.client.multiplayer.resolver.ServerAddress;
import net.minecraft.network.chat.CommonComponents;
import net.minecraft.network.chat.Component;
import net.minecraft.util.FormattedCharSequence;
import net.minecraft.util.Mth;
import org.jspecify.annotations.Nullable;

public class ServerBrowserScreen extends DropdownScreen {
	private static final int WHITE = 0xFFFFFFFF;
	private static final int GRAY = 0xFF808080;
	private static final int DARK_GRAY = 0xFF606060;
	private static final int GREEN = 0xFF55FF55;
	private static final int RED = 0xFFFF5555;
	private static final int MARGIN = 10;
	private static final int ROW_HEIGHT = 20;
	private static final int SEARCH_ROW_Y = 22;
	private static final int FILTER_ROW_Y = 46;
	private static final int LIST_TOP = 70;
	private static final int FOOTER_HEIGHT = 108;
	private static final int FOOTER_BUTTON_WIDTH = 90;
	private static final int ACTION_BUTTON_WIDTH = 120;
	private static final int SORT_BUTTON_WIDTH = 170;
	private static final int GAP = 4;
	private static final int SEARCH_DEBOUNCE_TICKS = 5;
	private static final long NOTICE_DURATION_MILLIS = 3000;

	private static Query rememberedQuery = Query.DEFAULT;

	private final Screen parent;
	private Query query;
	private final List<ServerDatabase.SortKey> sortKeys = new ArrayList<>(
		List.of(new ServerDatabase.SortKey(ServerDatabase.Sort.LAST_SEEN, true)));
	private @Nullable QueryResult result;
	private int ticksUntilSearch = -1;
	private long queryGeneration;
	private boolean loading;
	private volatile long downloadedBytes;
	private volatile long totalBytes = -1;
	private @Nullable String error;
	private @Nullable String notice;
	private long noticeExpiresAt;

	private ServerListWidget list;
	private EditBox searchBox;
	private Button joinButton;
	private Button addButton;
	private Button copyButton;
	private Button historyButton;
	private Button notesButton;
	private Button redownloadButton;
	private Button directionButton;
	private Button rescanButton;
	private Button whitelistButton;
	private Button syncButton;
	private boolean scannerBusy;
	private volatile @Nullable String scannerStatus;

	public ServerBrowserScreen(Screen parent) {
		this(parent, rememberedQuery);
	}

	public ServerBrowserScreen(Screen parent, Query query) {
		super(Component.literal("MCDB Server Browser"));
		this.parent = parent;
		this.query = query;
	}

	@Override
	protected void init() {
		WhitelistAutoUpdate.attach(this);
		int right = this.width - MARGIN;
		int directionX = right - ROW_HEIGHT;
		int sortX = directionX - GAP - SORT_BUTTON_WIDTH;

		this.searchBox = new EditBox(this.font, MARGIN, SEARCH_ROW_Y, sortX - GAP - MARGIN, ROW_HEIGHT, this.searchBox, Component.literal("Search"));
		this.searchBox.setMaxLength(256);
		this.searchBox.setHint(Component.literal("Search address, MOTD, version, player...").withStyle(EditBox.SEARCH_HINT_STYLE));
		this.searchBox.setValue(this.query.search());
		this.searchBox.setResponder(search -> this.ticksUntilSearch = SEARCH_DEBOUNCE_TICKS);
		this.addRenderableWidget(this.searchBox);

		this.addRenderableWidget(new Dropdown<>(sortX, SEARCH_ROW_Y, SORT_BUTTON_WIDTH, ROW_HEIGHT, "Sort", ServerDatabase.Sort.values(), this.primarySort(),
			this::toggleSort));
		this.directionButton = this.addRenderableWidget(Button.builder(
			directionArrow(this.primaryDescending()), button -> this.toggleDirection())
			.bounds(directionX, SEARCH_ROW_Y, ROW_HEIGHT, ROW_HEIGHT).build());

		int filterWidth = (right - MARGIN - 2 * GAP) / 3;
		this.addRenderableWidget(new Dropdown<>(MARGIN, FILTER_ROW_Y, filterWidth, ROW_HEIGHT, "Players", ServerDatabase.PlayersFilter.values(), this.query.players(),
			players -> this.setQuery(this.query.withPlayers(players))));
		this.addRenderableWidget(new Dropdown<>(MARGIN + filterWidth + GAP, FILTER_ROW_Y, filterWidth, ROW_HEIGHT, "Auth", ServerDatabase.AuthFilter.values(), this.query.auth(),
			auth -> this.setQuery(this.query.withAuth(auth))));
		this.addRenderableWidget(new Dropdown<>(right - filterWidth, FILTER_ROW_Y, filterWidth, ROW_HEIGHT, "Whitelist", ServerDatabase.WhitelistFilter.values(), this.query.whitelist(),
			whitelist -> this.setQuery(this.query.withWhitelist(whitelist))));

		this.list = this.addRenderableWidget(new ServerListWidget(this.width, this.height - FOOTER_HEIGHT - LIST_TOP, LIST_TOP));
		if (this.result != null) {
			this.list.setRows(this.result.rows());
		}

		int serverButtonCount = 5;
		int serverButtonWidth = Math.max(60, Math.min(FOOTER_BUTTON_WIDTH,
			(this.width - 2 * MARGIN - (serverButtonCount - 1) * GAP) / serverButtonCount));
		int step = serverButtonWidth + GAP;
		int serverRowY = this.height - 76;
		int serverRowX = (this.width - (serverButtonCount * serverButtonWidth
			+ (serverButtonCount - 1) * GAP)) / 2;
		this.joinButton = this.addRenderableWidget(this.footerButton(Component.translatable("selectServer.select"), serverRowX, serverRowY, serverButtonWidth, this::joinSelected));
		this.addButton = this.addRenderableWidget(this.footerButton(Component.literal("Add to List"), serverRowX + step, serverRowY, serverButtonWidth, this::addSelectedToServerList));
		this.copyButton = this.addRenderableWidget(this.footerButton(Component.literal("Copy IP"), serverRowX + 2 * step, serverRowY, serverButtonWidth, this::copySelected));
		this.historyButton = this.addRenderableWidget(this.footerButton(Component.literal("Seen Names"), serverRowX + 3 * step, serverRowY, serverButtonWidth, this::openSelectedHistory));
		this.notesButton = this.addRenderableWidget(this.footerButton(Component.literal("Notes"), serverRowX + 4 * step, serverRowY, serverButtonWidth, this::openSelectedNotes));

		int actionRowY = this.height - 52;
		int actionRowX = this.footerRowX(3, ACTION_BUTTON_WIDTH);
		this.rescanButton = this.addRenderableWidget(this.actionButton("Rescan",
			"Run mcscan.py --rescan for the selected server, then sync", actionRowX, actionRowY, this::rescanSelected));
		this.whitelistButton = this.addRenderableWidget(this.actionButton("Recheck Whitelist",
			"Run mcscan.py --recheck-whitelist for the selected server, then sync",
			actionRowX + ACTION_BUTTON_WIDTH + GAP, actionRowY, this::recheckWhitelistSelected));
		this.syncButton = this.addRenderableWidget(this.actionButton("Sync DB",
			"Run mcscan.py --sync, then reload the server list",
			actionRowX + 2 * (ACTION_BUTTON_WIDTH + GAP), actionRowY, this::syncDatabase));

		int screenRowY = this.height - 28;
		int screenRowX = this.footerRowX(4);
		this.redownloadButton = this.addRenderableWidget(this.footerButton(Component.literal("Redownload"), screenRowX, screenRowY, () -> this.load(true)));
		this.addRenderableWidget(this.footerButton(Component.literal("History"), screenRowX + step, screenRowY,
			() -> this.minecraft.gui.setScreen(new ServerHistoryScreen(this))));
		this.addRenderableWidget(this.footerButton(Component.literal("Settings"), screenRowX + 2 * step, screenRowY,
			() -> this.minecraft.gui.setScreen(new SettingsScreen(this))));
		this.addRenderableWidget(this.footerButton(CommonComponents.GUI_BACK, screenRowX + 3 * step, screenRowY, this::onClose));

		this.updateButtonStates();
		this.setInitialFocus(this.searchBox);

		if (this.result == null && !this.loading) {
			this.load(false);
		}
	}

	private int footerRowX(int buttonCount) {
		return this.footerRowX(buttonCount, FOOTER_BUTTON_WIDTH);
	}

	private int footerRowX(int buttonCount, int buttonWidth) {
		return (this.width - (buttonCount * buttonWidth + (buttonCount - 1) * GAP)) / 2;
	}

	private Button footerButton(Component label, int x, int y, Runnable action) {
		return this.footerButton(label, x, y, FOOTER_BUTTON_WIDTH, action);
	}

	private Button footerButton(Component label, int x, int y, int width, Runnable action) {
		return Button.builder(label, button -> action.run()).bounds(x, y, width, ROW_HEIGHT).build();
	}

	private Button actionButton(String label, String tooltip, int x, int y, Runnable action) {
		return Button.builder(Component.literal(label), button -> action.run())
			.bounds(x, y, ACTION_BUTTON_WIDTH, ROW_HEIGHT)
			.tooltip(Tooltip.create(Component.literal(tooltip)))
			.build();
	}

	private static Component directionArrow(boolean descending) {
		return Component.literal(descending ? "↓" : "↑");
	}

	private void load(boolean forceDownload) {
		this.loading = true;
		this.error = null;
		this.downloadedBytes = 0;
		this.totalBytes = -1;
		ServerDatabase.load(forceDownload, (downloaded, total) -> {
			this.downloadedBytes = downloaded;
			this.totalBytes = total;
		}).whenComplete((ignored, throwable) -> this.minecraft.execute(() -> {
			this.loading = false;
			if (throwable != null) {
				McdbBrowserClient.LOGGER.error("Failed to load server list", throwable);
				this.error = "Download failed: " + describe(throwable);
			} else {
				this.runQuery();
			}
		}));
	}

	private void setQuery(Query newQuery) {
		if (newQuery.equals(this.query)) {
			return;
		}
		this.query = newQuery;
		rememberedQuery = newQuery;
		if (!this.loading && ServerDatabase.isLoaded()) {
			this.runQuery();
		}
	}

	private void toggleSort(ServerDatabase.Sort sort) {
		int index = -1;
		for (int i = 0; i < this.sortKeys.size(); i++) {
			if (this.sortKeys.get(i).sort() == sort) {
				index = i;
				break;
			}
		}
		boolean descending = false;
		if (index >= 0) {
			descending = !this.sortKeys.get(index).descending();
			this.sortKeys.remove(index);
		}
		this.sortKeys.add(new ServerDatabase.SortKey(sort, descending));
		this.sortChanged();
	}

	private void toggleDirection() {
		if (this.sortKeys.isEmpty()) {
			this.sortKeys.add(new ServerDatabase.SortKey(
				ServerDatabase.Sort.LAST_SEEN, false));
		} else {
			ServerDatabase.SortKey primary = this.sortKeys.remove(this.sortKeys.size() - 1);
			this.sortKeys.add(new ServerDatabase.SortKey(primary.sort(),
				!primary.descending()));
		}
		this.sortChanged();
	}

	private void sortChanged() {
		this.updateDirectionButton();
		if (this.loading || !ServerDatabase.isLoaded()) {
			return;
		}
		if (this.result != null) {
			this.result.rows().sort(ServerDatabase.comparator(this.sortKeys));
			this.list.clearSelection();
			this.list.setRowsPreservingScroll(this.result.rows());
		} else {
			this.runQuery();
		}
	}

	private ServerDatabase.Sort primarySort() {
		return this.sortKeys.isEmpty() ? ServerDatabase.Sort.LAST_SEEN
			: this.sortKeys.get(this.sortKeys.size() - 1).sort();
	}

	private boolean primaryDescending() {
		return this.sortKeys.isEmpty()
			|| this.sortKeys.get(this.sortKeys.size() - 1).descending();
	}

	private void updateDirectionButton() {
		if (this.directionButton != null) {
			this.directionButton.setMessage(directionArrow(this.primaryDescending()));
		}
	}

	private void runQuery() {
		List<ServerDatabase.SortKey> requestedSort = List.copyOf(this.sortKeys);
		long generation = ++this.queryGeneration;
		ServerDatabase.query(this.query, requestedSort).whenComplete((queryResult, throwable) -> this.minecraft.execute(() -> {
			// A newer keystroke or filter change superseded this query. Applying
			// its rows would only wake up the list for a result nobody sees.
			if (generation != this.queryGeneration) {
				return;
			}
			if (throwable != null) {
				McdbBrowserClient.LOGGER.error("Server list query failed", throwable);
				this.error = "Query failed: " + describe(throwable);
			} else if (queryResult != null) {
				this.error = null;
				this.result = queryResult;
				if (!requestedSort.equals(this.sortKeys)) {
					queryResult.rows().sort(ServerDatabase.comparator(this.sortKeys));
				}
				this.list.setRows(queryResult.rows());
			}
		}));
	}

	private static String describe(Throwable throwable) {
		Throwable cause = throwable instanceof CompletionException && throwable.getCause() != null ? throwable.getCause() : throwable;
		return cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
	}

	@Override
	public void tick() {
		if (this.ticksUntilSearch >= 0 && this.ticksUntilSearch-- == 0) {
			this.setQuery(this.query.withSearch(this.searchBox.getValue()));
		}
		this.updateButtonStates();
	}

	private void updateButtonStates() {
		boolean hasSelection = this.list.hasSelection();
		boolean idle = !this.loading && !this.scannerBusy;
		this.joinButton.active = hasSelection && this.canJoin();
		this.addButton.active = hasSelection;
		this.copyButton.active = hasSelection;
		this.historyButton.active = hasSelection;
		this.notesButton.active = hasSelection;
		this.rescanButton.active = idle && hasSelection;
		this.whitelistButton.active = idle && hasSelection;
		this.syncButton.active = idle;
		this.redownloadButton.active = idle;
	}

	private @Nullable ServerRecord selectedServer() {
		return this.list.selectedServer();
	}

	private void joinSelected() {
		ServerRecord server = this.selectedServer();
		if (server != null) {
			this.join(server);
		}
	}

	private boolean canJoin() {
		return this.minecraft.level == null;
	}

	private void join(ServerRecord server) {
		if (!this.canJoin()) {
			return;
		}

		ServerData data = new ServerData(displayName(server), server.address(), ServerData.Type.OTHER);
		ConnectScreen.startConnecting(this, this.minecraft, ServerAddress.parseString(server.address()), data, false, null);
	}

	private void addSelectedToServerList() {
		ServerRecord server = this.selectedServer();
		if (server == null) {
			return;
		}

		if (SavedServers.add(this.minecraft, displayName(server), server.address())) {
			this.showNotice("Added " + server.address() + " to your server list");
		} else {
			this.showNotice(server.address() + " is already in your server list");
		}
	}

	private void openSelectedHistory() {
		ServerRecord server = this.selectedServer();
		if (server != null) {
			this.minecraft.gui.setScreen(new PlayerHistoryScreen(this, server.address()));
		}
	}

	private void openSelectedNotes() {
		ServerRecord server = this.selectedServer();
		if (server != null) {
			this.minecraft.gui.setScreen(new NotesScreen(this, server.address()));
		}
	}

	private void copySelected() {
		ServerRecord server = this.selectedServer();
		if (server != null) {
			this.minecraft.keyboardHandler.setClipboard(server.address());
			this.showNotice("Copied " + server.address());
		}
	}

	private void rescanSelected() {
		ServerRecord server = this.selectedServer();
		if (server != null) {
			this.runScannerAction("Rescanning " + server.address() + "…",
				() -> ScannerRunner.rescan(server.address(), this::setScannerStatus));
		}
	}

	private void recheckWhitelistSelected() {
		ServerRecord server = this.selectedServer();
		if (server == null) {
			return;
		}
		String address = server.address();
		this.runScannerAction("Checking whitelist for " + address + "…",
			() -> ScannerRunner.recheckWhitelist(address, this::setScannerStatus),
			() -> this.refreshWhitelist(address), true);
	}

	private void syncDatabase() {
		this.runScannerAction("Syncing shared DB…",
			() -> ScannerRunner.sync(this::setScannerStatus));
	}

	private void runScannerAction(String status, Supplier<CompletableFuture<ScannerRunner.Result>> action) {
		this.runScannerAction(status, action, () -> this.load(true));
	}

	private void runScannerAction(String status, Supplier<CompletableFuture<ScannerRunner.Result>> action,
			Runnable onSuccess) {
		this.runScannerAction(status, action, onSuccess, false);
	}

	private void runScannerAction(String status, Supplier<CompletableFuture<ScannerRunner.Result>> action,
			Runnable onSuccess, boolean refreshEvenOnFailure) {
		if (this.scannerBusy) {
			return;
		}
		this.scannerBusy = true;
		this.scannerStatus = status;
		this.error = null;
		this.notice = null;
		this.updateButtonStates();
		action.get().whenComplete((result, throwable) -> this.minecraft.execute(() -> {
			this.scannerBusy = false;
			this.scannerStatus = null;
			if (throwable != null) {
				this.error = "Scanner failed: " + describe(throwable);
				if (refreshEvenOnFailure) {
					onSuccess.run();
				}
			} else if (result == null || !result.ok()) {
				this.error = result == null ? "Scanner failed" : result.message();
				if (refreshEvenOnFailure) {
					onSuccess.run();
				}
			} else {
				this.showNotice(result.message());
				onSuccess.run();
			}
			this.updateButtonStates();
		}));
	}

	/** Read back the scanner verdict so the list updates without a full re-download. */
	private void refreshWhitelist(String address) {
		ScannerRunner.storedWhitelist(address).whenComplete((label, throwable) -> this.minecraft.execute(() -> {
			if (throwable != null) {
				McdbBrowserClient.LOGGER.warn("Could not read the whitelist result for {}", address, throwable);
				return;
			}
			if (label != null && !label.isBlank()) {
				this.applyWhitelist(address, label);
			}
			this.updateButtonStates();
		}));
	}

	/** Replace one loaded row's whitelist verdict and cache it for the next visit. */
	void applyWhitelist(String address, String label) {
		ServerDatabase.setWhitelist(address, label);
		if (this.result == null) {
			return;
		}
		List<ServerRecord> rows = this.result.rows();
		boolean changed = false;
		for (int i = 0; i < rows.size(); i++) {
			ServerRecord row = rows.get(i);
			if (row.address().equalsIgnoreCase(address)) {
				rows.set(i, row.withWhitelist(label));
				changed = true;
				break;
			}
		}
		if (changed) {
			this.list.setRowsPreservingScroll(rows);
		}
	}

	private void setScannerStatus(String line) {
		String text = line == null ? "" : line.strip();
		if (!text.isEmpty()) {
			this.scannerStatus = text.length() > 110 ? text.substring(0, 110) : text;
		}
	}

	private void showNotice(String text) {
		this.notice = text;
		this.noticeExpiresAt = System.currentTimeMillis() + NOTICE_DURATION_MILLIS;
	}

	private static String displayName(ServerRecord server) {
		String plainMotd = ChatFormatting.stripFormatting(server.motd());
		String firstLine = plainMotd == null ? "" : plainMotd.lines().map(String::strip).filter(line -> !line.isEmpty()).findFirst().orElse("");
		if (firstLine.isEmpty()) {
			return server.address();
		}
		return firstLine.length() > 40 ? firstLine.substring(0, 40) : firstLine;
	}

	@Override
	protected void extractForeground(GuiGraphicsExtractor graphics) {
		graphics.centeredText(this.font, this.title, this.width / 2, 8, WHITE);

		int statusY = this.height - FOOTER_HEIGHT + 8;
		if (this.loading) {
			graphics.centeredText(this.font, this.downloadStatus(), this.width / 2, statusY, GRAY);
		} else if (this.scannerBusy) {
			graphics.centeredText(this.font, this.scannerStatus == null ? "Working…" : this.scannerStatus,
				this.width / 2, statusY, GRAY);
		} else if (this.error != null) {
			graphics.centeredText(this.font, this.error, this.width / 2, statusY, RED);
		} else if (this.notice != null && System.currentTimeMillis() < this.noticeExpiresAt) {
			graphics.centeredText(this.font, this.notice, this.width / 2, statusY, GREEN);
		} else if (this.result != null) {
			graphics.centeredText(this.font, this.resultStatus(this.result), this.width / 2, statusY, GRAY);
		}
	}

	private String downloadStatus() {
		double downloadedMb = this.downloadedBytes / 1048576.0;
		if (this.totalBytes > 0) {
			return String.format(Locale.ROOT, "Downloading server list... %.1f / %.1f MB", downloadedMb, this.totalBytes / 1048576.0);
		}
		return String.format(Locale.ROOT, "Loading server list... %.1f MB", downloadedMb);
	}

	private String resultStatus(QueryResult result) {
		String status = String.format(Locale.ROOT, "%,d matching servers", result.rows().size());
		long downloadedAt = ServerDatabase.downloadedAtMillis();
		return downloadedAt > 0 ? status + " list downloaded " + timeAgo(downloadedAt / 1000.0) : status;
	}

	@Override
	public void onClose() {
		this.minecraft.gui.setScreen(this.parent);
	}

	static String timeAgo(double epochSeconds) {
		if (epochSeconds <= 0) {
			return "never";
		}

		long seconds = Math.max(0, (long) (System.currentTimeMillis() / 1000.0 - epochSeconds));
		if (seconds < 60) {
			return seconds + "s ago";
		} else if (seconds < 3600) {
			return seconds / 60 + "m ago";
		} else if (seconds < 86400) {
			return seconds / 3600 + "h ago";
		} else {
			return seconds / 86400 + "d ago";
		}
	}

	/**
	 * Vanilla's list walks every entry to place, measure, hover and draw rows, and placing them is quadratic.
	 * Every row here is the same height, so positions are computed directly to stay fast with ~200k servers.
	 */
	private class ServerListWidget extends ObjectSelectionList<ServerListWidget.Entry> {
		private static final int ENTRY_HEIGHT = 36;
		private static final int LIST_PADDING = 2;
		private static final int MAX_ROW_WIDTH = 420;
		private static final int MAX_VERSION_WIDTH = 140;
		private static final int TOOLTIP_NAME_LIMIT = 30;
		/** Rows kept ready above and below the viewport so small scrolls don't rebuild. */
		private static final int WINDOW_BUFFER = 4;

		private @Nullable Entry hoveredEntry;
		private double scrollOffset;
		private List<ServerRecord> rows = List.of();
		private int windowStart;
		private int windowEnd;
		private int selectedIndex = -1;
		private final Entry offscreenSelection = new Entry();

		ServerListWidget(int width, int height, int y) {
			super(ServerBrowserScreen.this.minecraft, width, height, y, ENTRY_HEIGHT);
		}

		/** Replace the result set, keeping a window of visible entries instead of one object per row. */
		void setRows(List<ServerRecord> servers) {
			this.rows = servers == null ? List.of() : servers;
			this.selectedIndex = -1;
			this.scrollOffset = 0;
			this.refreshWindow(true);
		}

		/** Reorder the result set without jumping the viewport (used when the sort changes). */
		void setRowsPreservingScroll(List<ServerRecord> servers) {
			this.rows = servers == null ? List.of() : servers;
			if (this.selectedIndex >= this.rows.size()) {
				this.selectedIndex = -1;
			}
			this.setScrollAmount(this.scrollOffset);
			this.refreshWindow(true);
		}

		void clearSelection() {
			this.selectedIndex = -1;
		}

		boolean hasSelection() {
			return this.selectedIndex >= 0 && this.selectedIndex < this.rows.size();
		}

		@Nullable ServerRecord selectedServer() {
			return this.hasSelection() ? this.rows.get(this.selectedIndex) : null;
		}

		@Override
		public @Nullable Entry getSelected() {
			if (!this.hasSelection()) {
				return null;
			}
			int index = this.selectedIndex;
			if (index >= this.windowStart && index < this.windowEnd
				&& index - this.windowStart < this.children().size()) {
				return this.children().get(index - this.windowStart);
			}
			// The selected row scrolled out of the window: keep the buttons enabled
			// by handing back a detached entry for that row.
			this.offscreenSelection.assign(index, this.rows.get(index));
			this.offscreenSelection.setX(this.getRowLeft());
			this.offscreenSelection.setY(this.firstRowY() + index * ENTRY_HEIGHT);
			this.offscreenSelection.setWidth(this.getRowWidth());
			this.offscreenSelection.setHeight(ENTRY_HEIGHT);
			return this.offscreenSelection;
		}

		@Override
		public void setSelected(@Nullable Entry entry) {
			this.selectedIndex = entry == null || entry.index < 0 || entry.index >= this.rows.size()
				? -1 : entry.index;
		}

		/** Keep children() limited to the visible rows plus a small buffer. */
		private void refreshWindow(boolean force) {
			if (this.rows == null) {
				return;
			}
			int count = this.rows.size();
			int firstRow = Math.max(0, Mth.floor(this.scrollOffset / ENTRY_HEIGHT));
			int visibleRows = (this.getHeight() + ENTRY_HEIGHT - 1) / ENTRY_HEIGHT + 1;
			int start = Math.max(0, firstRow - WINDOW_BUFFER);
			int end = Math.min(count, firstRow + visibleRows + WINDOW_BUFFER);
			List<Entry> entries = this.children();
			if (!force && start == this.windowStart && end == this.windowEnd
				&& entries.size() == end - start) {
				return;
			}

			int needed = end - start;
			if (entries.size() != needed) {
				// children() is an unmodifiable view, so resize through the
				// list's own helpers. Only the window is ever cleared, not all
				// ~250k result rows.
				this.clearEntries();
				for (int i = 0; i < needed; i++) {
					this.addEntry(new Entry(), ENTRY_HEIGHT);
				}
				entries = this.children();
			}

			int rowLeft = this.getRowLeft();
			int rowWidth = this.getRowWidth();
			int top = this.firstRowY();
			for (int i = 0; i < needed; i++) {
				int row = start + i;
				Entry entry = entries.get(i);
				entry.assign(row, this.rows.get(row));
				entry.setX(rowLeft);
				entry.setWidth(rowWidth);
				entry.setHeight(ENTRY_HEIGHT);
				entry.setY(top + row * ENTRY_HEIGHT);
			}
			this.windowStart = start;
			this.windowEnd = end;
		}

		@Override
		public int getRowWidth() {
			return Math.min(MAX_ROW_WIDTH, this.width - 4 * MARGIN);
		}

		private int firstRowY() {
			return this.getY() + LIST_PADDING - (int) this.scrollAmount();
		}

		private int rowIndexAt(double y) {
			return Mth.floor((y - this.firstRowY()) / ENTRY_HEIGHT);
		}

		@Override
		public int getNextY() {
			return this.firstRowY() + this.children().size() * ENTRY_HEIGHT;
		}

		@Override
		protected int contentHeight() {
			return (this.rows == null ? 0 : this.rows.size()) * ENTRY_HEIGHT + 2 * LIST_PADDING;
		}

		@Override
		public double scrollAmount() {
			return this.scrollOffset;
		}

		@Override
		public void setScrollAmount(double amount) {
			// AbstractSelectionList.setScrollAmount() calls repositionEntries(),
			// which would walk every entry on every wheel tick. Rows are positioned
			// from the scroll offset while drawing instead.
			this.scrollOffset = Math.max(0.0, Math.min(amount, this.maxScrollAmount()));
			this.refreshWindow(false);
		}

		@Override
		public void refreshScrollAmount() {
			this.setScrollAmount(this.scrollOffset);
		}

		@Override
		public int scrollBarY() {
			// The base implementation reads AbstractScrollArea's private
			// scrollAmount field, which this widget deliberately does not use.
			int max = this.maxScrollAmount();
			if (max == 0) {
				return this.getY();
			}
			int travel = Math.max(0, this.getHeight() - this.scrollerHeight());
			return Math.max(this.getY(),
				this.getY() + (int) (this.scrollOffset * travel / max));
		}

		@Override
		public Optional<GuiEventListener> getChildAt(double x, double y) {
			return Optional.ofNullable(this.entryAt(x, y));
		}

		private @Nullable Entry entryAt(double x, double y) {
			int index = this.rowIndexAt(y);
			if (index < 0 || index >= this.rows.size() || x < this.getRowLeft() || x >= this.getRowRight()) {
				return null;
			}
			if (index < this.windowStart || index >= this.windowEnd) {
				this.refreshWindow(true);
			}
			if (index < this.windowStart || index >= this.windowEnd) {
				return null;
			}
			return this.children().get(index - this.windowStart);
		}

		@Override
		protected @Nullable Entry getHovered() {
			return this.hoveredEntry;
		}

		@Override
		public void extractWidgetRenderState(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float a) {
			// Mirrors the superclass, minus its per-frame scan of every entry to find the hovered one
			this.hoveredEntry = this.isMouseOver(mouseX, mouseY) ? this.entryAt(mouseX, mouseY) : null;
			this.extractListBackground(graphics);
			this.enableScissor(graphics);
			this.extractListItems(graphics, mouseX, mouseY, a);
			graphics.disableScissor();
			this.extractListSeparators(graphics);
			this.extractScrollbar(graphics, mouseX, mouseY);
		}

		@Override
		protected void extractListItems(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float a) {
			this.refreshWindow(false);
			int first = Math.max(this.windowStart, Math.max(0, this.rowIndexAt(this.getY())));
			int last = Math.min(this.windowEnd - 1, this.rowIndexAt(this.getBottom()));
			int rowLeft = this.getRowLeft();
			int rowWidth = this.getRowWidth();
			int top = this.firstRowY();
			for (int row = first; row <= last; row++) {
				Entry entry = this.children().get(row - this.windowStart);
				// Only the rows about to be drawn get their coordinates
				// updated; the rest stay untouched until they scroll in.
				entry.setX(rowLeft);
				entry.setY(top + row * ENTRY_HEIGHT);
				entry.setWidth(rowWidth);
				this.extractItem(graphics, mouseX, mouseY, a, entry);
			}
		}

		@Override
		protected void extractItem(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float a, Entry entry) {
			if (entry.index == this.selectedIndex) {
				this.extractSelection(graphics, entry, this.isFocused() ? WHITE : GRAY);
			}
			entry.extractContent(graphics, mouseX, mouseY, entry == this.hoveredEntry, a);
		}

		class Entry extends ObjectSelectionList.Entry<Entry> {
			private static final Component SEPARATOR = Component.literal(" • ").withStyle(ChatFormatting.DARK_GRAY);

			ServerRecord server;
			int index = -1;
			// Built on first draw, since most rows are never scrolled into view
			private @Nullable String playerCount;
			private @Nullable Component motd;
			private @Nullable FormattedCharSequence motdLine;
			private int motdLineWidth = -1;
			private @Nullable Component details;
			private @Nullable List<Component> playersTooltip;
			private @Nullable List<Component> detailsTooltip;

			Entry() {
			}

			/** Recycled window slots point at a new row without allocating a new entry. */
			void assign(int index, ServerRecord server) {
				this.index = index;
				this.server = server;
				this.playerCount = null;
				this.motd = null;
				this.motdLine = null;
				this.motdLineWidth = -1;
				this.details = null;
				this.playersTooltip = null;
				this.detailsTooltip = null;
			}

			private void buildText(Font font) {
				ServerRecord server = this.server;
				this.playerCount = server.playersOnline() + "/" + server.maxPlayers();
				this.motd = Component.literal(String.join(" ", server.motd().strip().lines().map(String::strip).toList()));
				this.details = Component.empty()
					.append(Component.literal(font.plainSubstrByWidth(ChatFormatting.stripFormatting(server.version()), MAX_VERSION_WIDTH)).withStyle(ChatFormatting.GRAY))
					.append(SEPARATOR)
					.append(server.cracked()
						? Component.literal("Cracked").withStyle(ChatFormatting.GOLD)
						: Component.literal("Online mode").withStyle(ChatFormatting.AQUA))
					.append(SEPARATOR)
					.append(switch (server.whitelistState()) {
						case OPEN -> Component.literal("Open").withStyle(ChatFormatting.GREEN);
						case WHITELISTED -> Component.literal("Whitelisted").withStyle(ChatFormatting.RED);
						case UNKNOWN -> Component.literal("Whitelist unknown").withStyle(ChatFormatting.DARK_GRAY);
					});
			}

			@Override
			public void extractContent(GuiGraphicsExtractor graphics, int mouseX, int mouseY, boolean hovered, float a) {
				Font font = ServerBrowserScreen.this.font;
				if (this.playerCount == null) {
					this.buildText(font);
				}
				int left = this.getContentX();
				int top = this.getContentY();
				int right = this.getContentRight();
				int width = right - left;
				int playerCountX = right - font.width(this.playerCount);
				String lastSeen = "seen " + timeAgo(this.server.lastSeenEpochSeconds());

				graphics.text(font, this.playerCount, playerCountX, top + 1, this.server.playersOnline() > 0 ? GREEN : GRAY);
				graphics.text(font, font.plainSubstrByWidth(this.server.address(), playerCountX - left - 8), left, top + 1, WHITE);
				graphics.text(font, this.motdLine(font, width), left, top + 12, GRAY);
				graphics.text(font, this.details, left, top + 23, WHITE);
				graphics.text(font, lastSeen, right - font.width(lastSeen), top + 23, DARK_GRAY);

				if (!hovered) {
					return;
				}

				boolean overPlayerCount = mouseY < top + 10 && mouseX >= playerCountX;
				boolean overDetails = mouseY >= top + 22;
				if (overPlayerCount && !this.playersTooltip().isEmpty()) {
					graphics.setTooltipForNextFrame(font, this.playersTooltip(), Optional.empty(), mouseX, mouseY);
				} else if (overDetails) {
					graphics.setTooltipForNextFrame(font, this.detailsTooltip(), Optional.empty(), mouseX, mouseY);
				}
			}

			private FormattedCharSequence motdLine(Font font, int width) {
				if (this.motdLine == null || this.motdLineWidth != width) {
					// Splitting the Component (rather than measuring the raw string) honours legacy § codes such as bold
					List<FormattedCharSequence> lines = font.split(this.motd, width);
					this.motdLine = lines.isEmpty() ? FormattedCharSequence.EMPTY : lines.getFirst();
					this.motdLineWidth = width;
				}
				return this.motdLine;
			}

			private List<Component> playersTooltip() {
				if (this.playersTooltip == null) {
					List<String> now = this.server.playersNow();
					List<String> seenOnly = new ArrayList<>();
					for (String name : this.server.playersEver()) {
						if (!now.contains(name)) {
							seenOnly.add(name);
						}
					}
					this.playersTooltip = new ArrayList<>(now.size() + seenOnly.size() + 3);
					if (!now.isEmpty()) {
						this.playersTooltip.add(Component.literal("Players online now:").withStyle(ChatFormatting.YELLOW));
						addTooltipNames(this.playersTooltip, now);
					}
					if (!seenOnly.isEmpty()) {
						if (!this.playersTooltip.isEmpty()) {
							this.playersTooltip.add(Component.empty());
						}
						this.playersTooltip.add(Component.literal(now.isEmpty() ? "Seen names:" : "Also seen before:")
							.withStyle(ChatFormatting.YELLOW));
						addTooltipNames(this.playersTooltip, seenOnly);
					}
				}
				return this.playersTooltip;
			}

			private void addTooltipNames(List<Component> out, List<String> names) {
				int shown = Math.min(names.size(), TOOLTIP_NAME_LIMIT);
				for (int i = 0; i < shown; i++) {
					out.add(Component.literal(names.get(i)));
				}
				if (names.size() > shown) {
					out.add(Component.literal("... and " + (names.size() - shown) + " more (open Seen Names)")
						.withStyle(ChatFormatting.DARK_GRAY));
				}
			}

			private List<Component> detailsTooltip() {
				if (this.detailsTooltip == null) {
					this.detailsTooltip = new ArrayList<>();
					this.detailsTooltip.add(Component.literal(this.server.version()));
					this.detailsTooltip.add(Component.literal("Protocol " + this.server.protocol()).withStyle(ChatFormatting.GRAY));
					if (!this.server.whitelist().isEmpty()) {
						this.detailsTooltip.add(Component.literal(this.server.whitelist()).withStyle(ChatFormatting.GRAY));
					}
					this.detailsTooltip.add(Component.literal("First seen " + timeAgo(this.server.firstSeenEpochSeconds())).withStyle(ChatFormatting.GRAY));
					this.detailsTooltip.add(Component.literal("Seen " + this.server.timesSeen() + " times").withStyle(ChatFormatting.GRAY));
				}
				return this.detailsTooltip;
			}

			@Override
			public boolean mouseClicked(MouseButtonEvent event, boolean doubleClick) {
				if (doubleClick) {
					ServerBrowserScreen.this.join(this.server);
				}
				return super.mouseClicked(event, doubleClick);
			}

			@Override
			public boolean keyPressed(KeyEvent event) {
				if (event.isSelection()) {
					ServerBrowserScreen.this.join(this.server);
					return true;
				}
				return super.keyPressed(event);
			}

			@Override
			public Component getNarration() {
				return Component.literal(this.server.address());
			}
		}
	}
}
