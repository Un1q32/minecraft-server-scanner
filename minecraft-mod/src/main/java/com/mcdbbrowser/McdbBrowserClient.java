package com.mcdbbrowser;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.screen.v1.ScreenEvents;
import net.fabricmc.fabric.api.client.screen.v1.Screens;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.Tooltip;
import net.minecraft.client.gui.screens.PauseScreen;
import net.minecraft.client.gui.screens.multiplayer.JoinMultiplayerScreen;
import net.minecraft.network.chat.Component;
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

		ScreenEvents.AFTER_INIT.register((client, screen, width, height) -> {
			if (screen instanceof PauseScreen pauseScreen) {
				PauseMenuButtons.addTo(pauseScreen, client, Screens.getWidgets(screen));
				return;
			}
			if (!(screen instanceof JoinMultiplayerScreen)) {
				return;
			}

			Button button = Button.builder(Component.literal("Server DB"), b -> client.gui.setScreen(new ServerBrowserScreen(screen)))
				.bounds(McdbConfig.get().buttonX(width, BUTTON_WIDTH), McdbConfig.get().buttonY(height, BUTTON_HEIGHT), BUTTON_WIDTH, BUTTON_HEIGHT)
				.tooltip(Tooltip.create(Component.literal("Browse servers from " + ServerDatabase.DB_URL)))
				.build();
			Screens.getWidgets(screen).add(button);
		});
	}
}
