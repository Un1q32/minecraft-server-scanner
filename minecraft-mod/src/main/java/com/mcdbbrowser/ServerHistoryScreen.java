package com.mcdbbrowser;

import net.minecraft.ChatFormatting;
import net.minecraft.client.gui.Font;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.ObjectSelectionList;
import net.minecraft.client.gui.screens.ConnectScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.input.KeyEvent;
import net.minecraft.client.input.MouseButtonEvent;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.client.multiplayer.resolver.ServerAddress;
import net.minecraft.network.chat.CommonComponents;
import net.minecraft.network.chat.Component;
import org.jspecify.annotations.Nullable;

public class ServerHistoryScreen extends Screen {
	private static final int WHITE = 0xFFFFFFFF;
	private static final int GRAY = 0xFF808080;
	private static final int DARK_GRAY = 0xFF606060;
	private static final int GREEN = 0xFF55FF55;
	private static final int MARGIN = 10;
	private static final int ROW_HEIGHT = 20;
	private static final int LIST_TOP = 22;
	private static final int FOOTER_HEIGHT = 60;
	private static final int BUTTON_WIDTH = 90;
	private static final int GAP = 4;

	private final Screen parent;
	private @Nullable String notice;

	private HistoryList list;
	private Button joinButton;
	private Button addButton;
	private Button copyButton;

	public ServerHistoryScreen(Screen parent) {
		super(Component.literal("Server History"));
		this.parent = parent;
	}

	@Override
	protected void init() {
		this.list = this.addRenderableWidget(new HistoryList(this.width, this.height - FOOTER_HEIGHT - LIST_TOP, LIST_TOP));

		int footerY = this.height - 28;
		int step = BUTTON_WIDTH + GAP;
		int footerX = (this.width - (4 * BUTTON_WIDTH + 3 * GAP)) / 2;
		this.joinButton = this.addRenderableWidget(this.footerButton(Component.translatable("selectServer.select"), footerX, footerY, this::joinSelected));
		this.addButton = this.addRenderableWidget(this.footerButton(Component.literal("Add to List"), footerX + step, footerY, this::addSelectedToServerList));
		this.copyButton = this.addRenderableWidget(this.footerButton(Component.literal("Copy IP"), footerX + 2 * step, footerY, this::copySelected));
		this.addRenderableWidget(this.footerButton(CommonComponents.GUI_BACK, footerX + 3 * step, footerY, this::onClose));

		this.updateButtonStates();
	}

	private Button footerButton(Component label, int x, int y, Runnable action) {
		return Button.builder(label, button -> action.run()).bounds(x, y, BUTTON_WIDTH, ROW_HEIGHT).build();
	}

	@Override
	public void tick() {
		this.updateButtonStates();
	}

	private void updateButtonStates() {
		boolean hasSelection = this.list.getSelected() != null;
		this.joinButton.active = hasSelection && this.canJoin();
		this.addButton.active = hasSelection;
		this.copyButton.active = hasSelection;
	}

	private boolean canJoin() {
		return this.minecraft.level == null;
	}

	private void joinSelected() {
		HistoryList.Entry entry = this.list.getSelected();
		if (entry != null) {
			this.join(entry.server);
		}
	}

	private void join(ConnectionHistory.Entry server) {
		if (!this.canJoin()) {
			return;
		}

		ServerData data = new ServerData(server.name(), server.address(), ServerData.Type.OTHER);
		ConnectScreen.startConnecting(this, this.minecraft, ServerAddress.parseString(server.address()), data, false, null);
	}

	private void addSelectedToServerList() {
		HistoryList.Entry entry = this.list.getSelected();
		if (entry != null) {
			boolean added = SavedServers.add(this.minecraft, entry.server.name(), entry.server.address());
			this.notice = added ? "Added " + entry.server.address() + " to your server list" : entry.server.address() + " is already in your server list";
		}
	}

	private void copySelected() {
		HistoryList.Entry entry = this.list.getSelected();
		if (entry != null) {
			this.minecraft.keyboardHandler.setClipboard(entry.server.address());
			this.notice = "Copied " + entry.server.address();
		}
	}

	@Override
	public void extractRenderState(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float a) {
		super.extractRenderState(graphics, mouseX, mouseY, a);
		graphics.centeredText(this.font, this.title, this.width / 2, 8, WHITE);

		int statusY = this.height - FOOTER_HEIGHT + 10;
		if (this.notice != null) {
			graphics.centeredText(this.font, this.notice, this.width / 2, statusY, GREEN);
		} else if (this.list.children().isEmpty()) {
			graphics.centeredText(this.font, "Servers you join will appear here", this.width / 2, statusY, GRAY);
		}
	}

	@Override
	public void onClose() {
		this.minecraft.gui.setScreen(this.parent);
	}

	private class HistoryList extends ObjectSelectionList<HistoryList.Entry> {
		private static final int ENTRY_HEIGHT = 25;
		private static final int MAX_ROW_WIDTH = 420;

		HistoryList(int width, int height, int y) {
			super(ServerHistoryScreen.this.minecraft, width, height, y, ENTRY_HEIGHT);
			this.replaceEntries(ConnectionHistory.entries().stream().map(Entry::new).toList());
		}

		@Override
		public int getRowWidth() {
			return Math.min(MAX_ROW_WIDTH, this.width - 4 * MARGIN);
		}

		class Entry extends ObjectSelectionList.Entry<Entry> {
			final ConnectionHistory.Entry server;

			Entry(ConnectionHistory.Entry server) {
				this.server = server;
			}

			@Override
			public void extractContent(GuiGraphicsExtractor graphics, int mouseX, int mouseY, boolean hovered, float a) {
				Font font = ServerHistoryScreen.this.font;
				int left = this.getContentX();
				int top = this.getContentY();
				int right = this.getContentRight();
				String joined = ServerBrowserScreen.timeAgo(this.server.connectedAtMillis() / 1000.0);
				int joinedX = right - font.width(joined);

				graphics.text(font, font.plainSubstrByWidth(ChatFormatting.stripFormatting(this.server.name()), joinedX - left - 8), left, top + 1, WHITE);
				graphics.text(font, joined, joinedX, top + 1, DARK_GRAY);
				graphics.text(font, font.plainSubstrByWidth(this.server.address(), right - left), left, top + 12, GRAY);
			}

			@Override
			public boolean mouseClicked(MouseButtonEvent event, boolean doubleClick) {
				if (doubleClick) {
					ServerHistoryScreen.this.join(this.server);
				}
				return super.mouseClicked(event, doubleClick);
			}

			@Override
			public boolean keyPressed(KeyEvent event) {
				if (event.isSelection()) {
					ServerHistoryScreen.this.join(this.server);
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
