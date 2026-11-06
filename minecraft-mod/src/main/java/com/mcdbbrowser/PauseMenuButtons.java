package com.mcdbbrowser;

import java.util.List;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.components.AbstractWidget;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.screens.PauseScreen;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.client.multiplayer.resolver.ServerAddress;
import net.minecraft.network.chat.Component;

final class PauseMenuButtons {
	private static final int MARGIN = 5;
	private static final int WIDTH = 110;
	private static final int HEIGHT = 20;
	private static final int SPACING = 24;

	private PauseMenuButtons() {
	}

	static void addTo(PauseScreen screen, Minecraft minecraft, List<AbstractWidget> widgets) {
		if (alreadyPresent(widgets)) {
			return;
		}
		ServerData server = minecraft.getCurrentServer();
		if (!screen.showsPauseMenu() || server == null || minecraft.isLocalServer()) {
			return;
		}

		widgets.add(Button.builder(Component.literal("Copy IP"), button -> {
			minecraft.keyboardHandler.setClipboard(server.ip);
			button.setMessage(Component.literal("Copied!"));
		}).bounds(MARGIN, MARGIN, WIDTH, HEIGHT).build());

		boolean saved = SavedServers.contains(minecraft, server.ip);
		Button addButton = Button.builder(Component.literal(saved ? "In Server List" : "Add to Server List"), button -> {
			SavedServers.add(minecraft, server.name, server.ip);
			button.setMessage(Component.literal("In Server List"));
			button.active = false;
		}).bounds(MARGIN, MARGIN + SPACING, WIDTH, HEIGHT).build();
		addButton.active = !saved;
		widgets.add(addButton);

		widgets.add(Button.builder(Component.literal("Find in Server DB"),
			button -> minecraft.gui.setScreen(new ServerBrowserScreen(screen, ServerDatabase.Query.DEFAULT.withSearch(server.ip))))
			.bounds(MARGIN, MARGIN + 2 * SPACING, WIDTH, HEIGHT).build());

		ServerAddress address = ServerAddress.parseString(server.ip);
		String hostAndPort = address.getHost() + ":" + address.getPort();
		widgets.add(Button.builder(Component.literal("Seen Names"),
			button -> minecraft.gui.setScreen(new PlayerHistoryScreen(screen, hostAndPort)))
			.bounds(MARGIN, MARGIN + 3 * SPACING, WIDTH, HEIGHT).build());
		widgets.add(Button.builder(Component.literal("Notes"),
			button -> minecraft.gui.setScreen(new NotesScreen(screen, hostAndPort)))
			.bounds(MARGIN, MARGIN + 4 * SPACING, WIDTH, HEIGHT).build());
	}

	/** Fabric re-fires AFTER_INIT on resize, and resize keeps the existing widgets. */
	private static boolean alreadyPresent(List<AbstractWidget> widgets) {
		for (AbstractWidget widget : widgets) {
			if (widget instanceof Button button
					&& "Find in Server DB".equals(button.getMessage().getString())) {
				return true;
			}
		}
		return false;
	}
}
