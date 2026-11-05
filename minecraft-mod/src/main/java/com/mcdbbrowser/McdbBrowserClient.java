package com.mcdbbrowser;

import java.util.List;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.client.screen.v1.ScreenEvents;
import net.fabricmc.fabric.api.client.screen.v1.Screens;
import net.minecraft.client.gui.components.AbstractWidget;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.Tooltip;
import net.minecraft.client.gui.screens.PauseScreen;
import net.minecraft.client.gui.screens.multiplayer.JoinMultiplayerScreen;
import net.minecraft.network.chat.Component;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class McdbBrowserClient implements ClientModInitializer {
	public static final String MOD_ID = "mcdbbrowser";
	public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);
	private static final int BUTTON_WIDTH = 100;
	private static final int BUTTON_HEIGHT = 20;

	@Override
	public void onInitializeClient() {
		ServerDatabase.deleteLeftoverFiles();
		McdbConfig.load();
		ConnectionHistory.load();
		ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> WhitelistAutoUpdate.onJoined());

		ScreenEvents.AFTER_INIT.register((client, screen, width, height) -> {
			if (screen instanceof PauseScreen pauseScreen) {
				PauseMenuButtons.addTo(pauseScreen, client, Screens.getWidgets(screen));
				return;
			}
			if (!(screen instanceof JoinMultiplayerScreen)) {
				return;
			}

			var widgets = Screens.getWidgets(screen);
			// AFTER_INIT also fires when Fabric forwards a resize, so move the
			// existing button instead of stacking another copy on top of it.
			Button existing = findServerDbButton(widgets);
			if (existing != null) {
				existing.setX(McdbConfig.get().buttonX(width, BUTTON_WIDTH));
				existing.setY(McdbConfig.get().buttonY(height, BUTTON_HEIGHT));
				existing.setWidth(BUTTON_WIDTH);
				existing.setHeight(BUTTON_HEIGHT);
				return;
			}
			Button button = Button.builder(Component.literal("Server DB"), b -> client.gui.setScreen(new ServerBrowserScreen(screen)))
				.bounds(McdbConfig.get().buttonX(width, BUTTON_WIDTH), McdbConfig.get().buttonY(height, BUTTON_HEIGHT), BUTTON_WIDTH, BUTTON_HEIGHT)
				.tooltip(Tooltip.create(Component.literal("Browse servers from " + ServerDatabase.DB_URL)))
				.build();
			widgets.add(button);
		});
	}

	private static @Nullable Button findServerDbButton(List<AbstractWidget> widgets) {
		for (AbstractWidget widget : widgets) {
			if (widget instanceof Button button
					&& "Server DB".equals(button.getMessage().getString())) {
				return button;
			}
		}
		return null;
	}
}
