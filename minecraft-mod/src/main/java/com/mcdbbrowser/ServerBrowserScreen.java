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
	private static final int SORT_BUTTON_WIDTH = 130;
	private static final int GAP = 4;
	private static final int SEARCH_DEBOUNCE_TICKS = 5;
	private static final long NOTICE_DURATION_MILLIS = 3000;

	private static Query rememberedQuery = Query.DEFAULT;

	private final Screen parent;
	private Query query;
	private @Nullable QueryResult result;
	private int ticksUntilSearch = -1;
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
	private Button redownloadButton;
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
		int right = this.width - MARGIN;
		int directionX = right - ROW_HEIGHT;
		int sortX = directionX - GAP - SORT_BUTTON_WIDTH;

		this.searchBox = new EditBox(this.font, MARGIN, SEARCH_ROW_Y, sortX - GAP - MARGIN, ROW_HEIGHT, this.searchBox, Component.literal("Search"));
		this.searchBox.setMaxLength(256);
		this.searchBox.setHint(Component.literal("Search address, MOTD, version, player...").withStyle(EditBox.SEARCH_HINT_STYLE));
		this.searchBox.setValue(this.query.search());
		this.searchBox.setResponder(search -> this.ticksUntilSearch = SEARCH_DEBOUNCE_TICKS);
		this.addRenderableWidget(this.searchBox);

		this.addRenderableWidget(new Dropdown<>(sortX, SEARCH_ROW_Y, SORT_BUTTON_WIDTH, ROW_HEIGHT, "Sort", ServerDatabase.Sort.values(), this.query.sort(),
			sort -> this.setQuery(this.query.withSort(sort))));
		this.addRenderableWidget(Button.builder(directionArrow(this.query.descending()), button -> {
			this.setQuery(this.query.withDescending(!this.query.descending()));
			button.setMessage(directionArrow(this.query.descending()));
		}).bounds(directionX, SEARCH_ROW_Y, ROW_HEIGHT, ROW_HEIGHT).build());

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

		int step = FOOTER_BUTTON_WIDTH + GAP;
		int serverRowY = this.height - 76;
		int serverRowX = this.footerRowX(4);
		this.joinButton = this.addRenderableWidget(this.footerButton(Component.translatable("selectServer.select"), serverRowX, serverRowY, this::joinSelected));
		this.addButton = this.addRenderableWidget(this.footerButton(Component.literal("Add to List"), serverRowX + step, serverRowY, this::addSelectedToServerList));
		this.copyButton = this.addRenderableWidget(this.footerButton(Component.literal("Copy IP"), serverRowX + 2 * step, serverRowY, this::copySelected));
		this.historyButton = this.addRenderableWidget(this.footerButton(Component.literal("Player History"), serverRowX + 3 * step, serverRowY, this::openSelectedHistory));

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
		return Button.builder(label, button -> action.run()).bounds(x, y, FOOTER_BUTTON_WIDTH, ROW_HEIGHT).build();
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

		boolean sortOnly = this.query.withSort(newQuery.sort())
			.withDescending(newQuery.descending()).equals(newQuery);
		this.query = newQuery;
		rememberedQuery = newQuery;
		if (!this.loading && ServerDatabase.isLoaded()) {
			if (sortOnly && this.result != null) {
				// The SQL result is already filtered; re-sort it in Java
				// instead of re-querying SQLite and rebuilding every row.
				this.result.rows().sort(this.query.comparator());
				this.list.updateRows(this.result.rows());
			} else {
				this.runQuery();
			}
		}
	}

	private void runQuery() {
		ServerDatabase.query(this.query).whenComplete((queryResult, throwable) -> this.minecraft.execute(() -> {
			if (throwable != null) {
				McdbBrowserClient.LOGGER.error("Server list query failed", throwable);
				this.error = "Query failed: " + describe(throwable);
			} else if (queryResult != null) {
				this.error = null;
				this.result = queryResult;
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
		boolean hasSelection = this.list.getSelected() != null;
		boolean idle = !this.loading && !this.scannerBusy;
		this.joinButton.active = hasSelection && this.canJoin();
		this.addButton.active = hasSelection;
		this.copyButton.active = hasSelection;
		this.historyButton.active = hasSelection;
		this.rescanButton.active = idle && hasSelection;
		this.whitelistButton.active = idle && hasSelection;
		this.syncButton.active = idle;
		this.redownloadButton.active = idle;
	}

	private @Nullable ServerRecord selectedServer() {
		ServerListWidget.Entry entry = this.list.getSelected();
		return entry == null ? null : entry.server;
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
		if (server != null) {
			this.runScannerAction("Checking whitelist for " + server.address() + "…",
				() -> ScannerRunner.recheckWhitelist(server.address(), this::setScannerStatus));
		}
	}

	private void syncDatabase() {
		this.runScannerAction("Syncing shared DB…",
			() -> ScannerRunner.sync(this::setScannerStatus));
	}

	private void runScannerAction(String status, Supplier<CompletableFuture<ScannerRunner.Result>> action) {
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
			} else if (result == null || !result.ok()) {
				this.error = result == null ? "Scanner failed" : result.message();
			} else {
				this.showNotice(result.message());
				// mcscan.py --sync has updated the shared DB; pull the result.
				this.load(true);
			}
			this.updateButtonStates();
		}));
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

		private @Nullable Entry hoveredEntry;
		private double scrollOffset;

		ServerListWidget(int width, int height, int y) {
			super(ServerBrowserScreen.this.minecraft, width, height, y, ENTRY_HEIGHT);
		}

		void setRows(List<ServerRecord> servers) {
			if (this.children().size() == servers.size()) {
				this.updateRows(servers);
			} else {
				this.replaceEntries(servers.stream().map(Entry::new).toList());
			}
			this.setScrollAmount(0);
		}

		/** Reorder existing row objects to match a new list, preserving scroll. */
		void updateRows(List<ServerRecord> servers) {
			List<Entry> entries = this.children();
			int count = Math.min(entries.size(), servers.size());
			for (int i = 0; i < count; i++) {
				entries.get(i).setServer(servers.get(i));
			}
			this.hoveredEntry = null;
			this.setSelected(null);
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
			return this.children().size() * ENTRY_HEIGHT + 2 * LIST_PADDING;
		}

		@Override
		public double scrollAmount() {
			return this.scrollOffset;
		}

		@Override
		public void setScrollAmount(double amount) {
			// AbstractSelectionList.setScrollAmount() calls repositionEntries(),
			// which walks every one of the ~200k entries on every wheel tick.
			// Rows are positioned from the scroll offset while drawing instead.
			this.scrollOffset = Math.max(0.0, Math.min(amount, this.maxScrollAmount()));
		}

		@Override
		public Optional<GuiEventListener> getChildAt(double x, double y) {
			return Optional.ofNullable(this.entryAt(x, y));
		}

		private @Nullable Entry entryAt(double x, double y) {
			int index = this.rowIndexAt(y);
			if (index < 0 || index >= this.children().size() || x < this.getRowLeft() || x >= this.getRowRight()) {
				return null;
			}
			return this.children().get(index);
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
			List<Entry> entries = this.children();
			int first = Math.max(0, this.rowIndexAt(this.getY()));
			int last = Math.min(entries.size() - 1, this.rowIndexAt(this.getBottom()));
			int rowLeft = this.getRowLeft();
			int rowWidth = this.getRowWidth();
			int top = this.firstRowY();
			for (int i = first; i <= last; i++) {
				Entry entry = entries.get(i);
				// Only the rows about to be drawn get their coordinates
				// updated; the rest stay untouched until they scroll in.
				entry.setX(rowLeft);
				entry.setY(top + i * ENTRY_HEIGHT);
				entry.setWidth(rowWidth);
				this.extractItem(graphics, mouseX, mouseY, a, entry);
			}
		}

		@Override
		protected void extractItem(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float a, Entry entry) {
			if (this.getSelected() == entry) {
				this.extractSelection(graphics, entry, this.isFocused() ? WHITE : GRAY);
			}
			entry.extractContent(graphics, mouseX, mouseY, entry == this.hoveredEntry, a);
		}

		class Entry extends ObjectSelectionList.Entry<Entry> {
			private static final Component SEPARATOR = Component.literal(" • ").withStyle(ChatFormatting.DARK_GRAY);

			ServerRecord server;
			// Built on first draw, since most rows are never scrolled into view
			private @Nullable String playerCount;
			private @Nullable Component motd;
			private @Nullable FormattedCharSequence motdLine;
			private int motdLineWidth = -1;
			private @Nullable Component details;
			private @Nullable List<Component> playersTooltip;
			private @Nullable List<Component> detailsTooltip;

			Entry(ServerRecord server) {
				this.server = server;
			}

			void setServer(ServerRecord server) {
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
					List<String> names = this.server.playersNow();
					this.playersTooltip = new ArrayList<>(names.size() + 1);
					if (!names.isEmpty()) {
						this.playersTooltip.add(Component.literal("Players seen online:").withStyle(ChatFormatting.YELLOW));
						names.forEach(name -> this.playersTooltip.add(Component.literal(name)));
					}
				}
				return this.playersTooltip;
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
