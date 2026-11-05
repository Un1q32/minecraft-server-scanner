package com.mcdbbrowser;

import java.io.IOException;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.CommonComponents;
import net.minecraft.network.chat.Component;

/** Shared-DB URL and token, written to the bundled scanner's netdb.json. */
public class DatabaseSettingsScreen extends DropdownScreen {
	private static final int FIELD_WIDTH = 300;
	private static final int ROW_HEIGHT = 20;
	private static final int ROW_SPACING = 26;

	private final Screen parent;
	private EditBox urlBox;
	private EditBox tokenBox;
	private String status = "";

	public DatabaseSettingsScreen(Screen parent) {
		super(Component.literal("Shared DB Credentials"));
		this.parent = parent;
	}

	@Override
	protected void init() {
		int x = (this.width - FIELD_WIDTH) / 2;
		int y = this.height / 2 - 34;
		BundledScanner.Credentials credentials = BundledScanner.loadCredentials();

		this.urlBox = new EditBox(this.font, x, y, FIELD_WIDTH, ROW_HEIGHT,
			Component.literal("Shared DB URL"));
		this.urlBox.setMaxLength(512);
		this.urlBox.setHint(Component.literal("Shared DB URL (https://db.example.com)"));
		this.urlBox.setValue(credentials.url());
		this.addRenderableWidget(this.urlBox);

		this.tokenBox = new EditBox(this.font, x, y + ROW_SPACING,
			FIELD_WIDTH, ROW_HEIGHT, Component.literal("Shared DB token"));
		this.tokenBox.setMaxLength(512);
		this.tokenBox.setHint(Component.literal("Shared DB token"));
		this.tokenBox.setValue(credentials.token());
		this.addRenderableWidget(this.tokenBox);

		int buttonWidth = (FIELD_WIDTH - 4) / 2;
		this.addRenderableWidget(Button.builder(Component.literal("Save"), button -> this.save())
			.bounds(x, y + 2 * ROW_SPACING + 6, buttonWidth, ROW_HEIGHT).build());
		this.addRenderableWidget(Button.builder(CommonComponents.GUI_BACK, button -> this.onClose())
			.bounds(x + FIELD_WIDTH - buttonWidth, y + 2 * ROW_SPACING + 6,
				buttonWidth, ROW_HEIGHT).build());
	}

	private void save() {
		try {
			BundledScanner.saveCredentials(this.urlBox.getValue(), this.tokenBox.getValue());
			this.status = "Saved shared DB credentials";
		} catch (IOException e) {
			this.status = "Could not save: " + e.getMessage();
			McdbBrowserClient.LOGGER.warn("Could not save shared DB credentials", e);
		}
	}

	@Override
	protected void extractForeground(GuiGraphicsExtractor graphics) {
		graphics.centeredText(this.font, this.title, this.width / 2, 20, 0xFFFFFFFF);
		int y = this.height / 2 - 34;
		graphics.centeredText(this.font, "Used by Sync DB, Rescan and Recheck Whitelist",
			this.width / 2, y - 22, 0xFFA0A0A0);
		graphics.centeredText(this.font, "Stored in " + BundledScanner.configFile(),
			this.width / 2, y - 10, 0xFF808080);
		if (!this.status.isEmpty()) {
			graphics.centeredText(this.font, this.status, this.width / 2,
				y + 2 * ROW_SPACING + 32, 0xFF55FF55);
		}
	}

	@Override
	public void onClose() {
		this.minecraft.gui.setScreen(this.parent);
	}
}
