package com.mcdbbrowser;

import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletionException;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.components.ObjectSelectionList;
import net.minecraft.client.gui.screens.ConfirmScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.input.MouseButtonEvent;
import net.minecraft.network.chat.CommonComponents;
import net.minecraft.network.chat.Component;
import org.jspecify.annotations.Nullable;

public class PlayerHistoryScreen extends Screen {
	private static final int WHITE = 0xFFFFFFFF;
	private static final int GRAY = 0xFF808080;
	private static final int GREEN = 0xFF55FF55;
	private static final int RED = 0xFFFF5555;
	private static final int MARGIN = 10;
	private static final int ROW_HEIGHT = 20;
	private static final int FILTER_Y = 22;
	private static final int LIST_TOP = 46;
	private static final int FOOTER_HEIGHT = 60;
	private static final int BUTTON_WIDTH = 100;
	private static final int GAP = 4;
	private static final boolean METEOR_LOADED = FabricLoader.getInstance().isModLoaded(MeteorAlts.MOD_ID);

	private final Screen parent;
	private final String hostAndPort;
	private @Nullable List<String> names;
	private boolean loading;
	private @Nullable String status;
	private int statusColor = GRAY;

	private EditBox filterBox;
	private NameList list;
	private Button copyButton;
	private @Nullable Button loginButton;
	private @Nullable Button meteorButton;
	private boolean meteorBusy;

	public PlayerHistoryScreen(Screen parent, String hostAndPort) {
		super(Component.literal("Seen names: " + hostAndPort));
		this.parent = parent;
		this.hostAndPort = hostAndPort;
	}

	@Override
	protected void init() {
		this.filterBox = new EditBox(this.font, MARGIN, FILTER_Y, this.width - 2 * MARGIN, ROW_HEIGHT, this.filterBox, Component.literal("Filter"));
		this.filterBox.setHint(Component.literal("Filter names...").withStyle(EditBox.SEARCH_HINT_STYLE));
		this.filterBox.setResponder(filter -> this.refreshList());
		this.addRenderableWidget(this.filterBox);

		this.list = this.addRenderableWidget(new NameList(this.width, this.height - FOOTER_HEIGHT - LIST_TOP, LIST_TOP));
		this.refreshList();

		int buttonCount = METEOR_LOADED ? 4 : 2;
		int footerY = this.height - 28;
		int buttonWidth = Math.max(70,
			Math.min(BUTTON_WIDTH, (this.width - 2 * MARGIN - (buttonCount - 1) * GAP) / buttonCount));
		int footerX = (this.width - (buttonCount * buttonWidth + (buttonCount - 1) * GAP)) / 2;
		int step = buttonWidth + GAP;
		int x = footerX;
		if (METEOR_LOADED) {
			this.loginButton = this.addRenderableWidget(Button.builder(Component.literal("Login as Name"), button -> this.loginSelected())
				.bounds(x, footerY, buttonWidth, ROW_HEIGHT).build());
			x += step;
		}
		this.copyButton = this.addRenderableWidget(Button.builder(Component.literal("Copy Name"), button -> this.copySelected())
			.bounds(x, footerY, buttonWidth, ROW_HEIGHT).build());
		x += step;
		if (METEOR_LOADED) {
			this.meteorButton = this.addRenderableWidget(Button.builder(Component.literal("Add All as Alts"), button -> this.confirmAddToMeteor())
				.bounds(x, footerY, buttonWidth, ROW_HEIGHT).build());
			x += step;
		}
		this.addRenderableWidget(Button.builder(CommonComponents.GUI_BACK, button -> this.onClose())
			.bounds(x, footerY, buttonWidth, ROW_HEIGHT).build());

		this.setInitialFocus(this.filterBox);
		if (this.names == null && !this.loading) {
			this.load();
		}
	}

	private void load() {
		this.loading = true;
		this.showStatus("Loading...", GRAY);
		ServerDatabase.load(false, (downloaded, total) -> {})
			.thenCompose(ignored -> ServerDatabase.historicalPlayers(this.hostAndPort))
			.whenComplete((names, throwable) -> this.minecraft.execute(() -> {
				this.loading = false;
				if (throwable != null) {
					McdbBrowserClient.LOGGER.error("Failed to load player history for {}", this.hostAndPort, throwable);
					Throwable cause = throwable instanceof CompletionException && throwable.getCause() != null ? throwable.getCause() : throwable;
					this.showStatus("Failed to load: " + cause.getMessage(), RED);
				} else if (names == null) {
					this.showStatus("This server isn't in the database", GRAY);
				} else {
					this.names = names.stream().sorted(String.CASE_INSENSITIVE_ORDER).toList();
					this.status = null;
					this.refreshList();
				}
			}));
	}

	private void refreshList() {
		if (this.names == null) {
			return;
		}

		String filter = this.filterBox.getValue().strip().toLowerCase(Locale.ROOT);
		this.list.setNames(filter.isEmpty() ? this.names : this.names.stream().filter(name -> name.toLowerCase(Locale.ROOT).contains(filter)).toList());
	}

	private void copySelected() {
		NameList.Entry entry = this.list.getSelected();
		if (entry != null) {
			this.minecraft.keyboardHandler.setClipboard(entry.name);
			this.showStatus("Copied " + entry.name, GREEN);
		}
	}

	private List<String> shownNames() {
		return this.list.children().stream().map(entry -> entry.name).toList();
	}

	private void confirmAddToMeteor() {
		List<String> names = this.shownNames();
		Component title = Component.literal(String.format(Locale.ROOT, "Add %,d players to Meteor alts?", names.size()));
		Component message = Component.literal("Each name is added as a cracked account. Names that aren't valid Java usernames are skipped.");
		this.minecraft.gui.setScreen(new ConfirmScreen(confirmed -> {
			this.minecraft.gui.setScreen(this);
			if (confirmed) {
				this.addToMeteor(names);
			}
		}, title, message));
	}

	private void loginSelected() {
		NameList.Entry entry = this.list.getSelected();
		if (entry == null) {
			return;
		}
		String name = entry.name;
		this.meteorBusy = true;
		this.showStatus("Signing in as " + name + "...", GRAY);
		MeteorAlts.loginCracked(name).whenComplete((result, throwable) -> this.minecraft.execute(() -> {
			this.meteorBusy = false;
			if (throwable != null) {
				McdbBrowserClient.LOGGER.error("Failed to sign in to Meteor as {}", name, throwable);
				this.showStatus("Could not sign in as " + name + ": " + throwable.getMessage(), RED);
			} else if (result == null || !result.loggedIn()) {
				String error = result == null || result.error() == null ? "unknown error" : result.error();
				this.showStatus("Could not sign in as " + name + ": " + error, RED);
			} else {
				String suffix = this.minecraft.level == null ? "" : " (applies to the next server you join)";
				this.showStatus("Signed in as " + result.name() + " with a cracked account" + suffix, GREEN);
			}
		}));
	}

	private void addToMeteor(List<String> names) {
		this.meteorBusy = true;
		this.showStatus("Adding to Meteor alts...", GRAY);
		MeteorAlts.addCracked(names).whenComplete((result, throwable) -> this.minecraft.execute(() -> {
			this.meteorBusy = false;
			if (throwable != null) {
				McdbBrowserClient.LOGGER.error("Failed to add Meteor alts", throwable);
				this.showStatus("Failed to add Meteor alts: " + throwable.getMessage(), RED);
			} else {
				this.showStatus(String.format(Locale.ROOT, "Added %,d Meteor alts (%,d already there, %,d invalid names skipped)",
					result.added(), result.alreadyPresent(), result.invalid()), GREEN);
			}
		}));
	}

	private void showStatus(String text, int color) {
		this.status = text;
		this.statusColor = color;
	}

	@Override
	public void tick() {
		boolean hasSelection = this.list.getSelected() != null;
		this.copyButton.active = hasSelection;
		if (this.loginButton != null) {
			this.loginButton.active = !this.meteorBusy && hasSelection;
		}
		if (this.meteorButton != null) {
			this.meteorButton.active = !this.meteorBusy && !this.list.children().isEmpty();
		}
	}

	@Override
	public void extractRenderState(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float a) {
		super.extractRenderState(graphics, mouseX, mouseY, a);
		graphics.centeredText(this.font, this.title, this.width / 2, 8, WHITE);

		int statusY = this.height - FOOTER_HEIGHT + 10;
		if (this.status != null) {
			graphics.centeredText(this.font, this.status, this.width / 2, statusY, this.statusColor);
		} else if (this.names != null) {
			String count = this.names.isEmpty()
				? "No players have been seen on this server"
				: String.format(Locale.ROOT, "%,d of %,d players seen on this server", this.list.children().size(), this.names.size());
			graphics.centeredText(this.font, count, this.width / 2, statusY, GRAY);
		}
	}

	@Override
	public void onClose() {
		this.minecraft.gui.setScreen(this.parent);
	}

	private class NameList extends ObjectSelectionList<NameList.Entry> {
		private static final int ENTRY_HEIGHT = 12;
		private static final int ROW_WIDTH = 400;

		NameList(int width, int height, int y) {
			super(PlayerHistoryScreen.this.minecraft, width, height, y, ENTRY_HEIGHT);
		}

		void setNames(List<String> names) {
			this.replaceEntries(names.stream().map(Entry::new).toList());
			this.setScrollAmount(0);
		}

		@Override
		public int getRowWidth() {
			return Math.min(ROW_WIDTH, this.width - 4 * MARGIN);
		}

		class Entry extends ObjectSelectionList.Entry<Entry> {
			final String name;

			Entry(String name) {
				this.name = name;
			}

			@Override
			public void extractContent(GuiGraphicsExtractor graphics, int mouseX, int mouseY, boolean hovered, float a) {
				graphics.text(PlayerHistoryScreen.this.font, this.name, this.getContentX(), this.getContentY(), WHITE);
			}

			@Override
			public boolean mouseClicked(MouseButtonEvent event, boolean doubleClick) {
				if (doubleClick) {
					PlayerHistoryScreen.this.minecraft.keyboardHandler.setClipboard(this.name);
					PlayerHistoryScreen.this.showStatus("Copied " + this.name, GREEN);
				}
				return super.mouseClicked(event, doubleClick);
			}

			@Override
			public Component getNarration() {
				return Component.literal(this.name);
			}
		}
	}
}
