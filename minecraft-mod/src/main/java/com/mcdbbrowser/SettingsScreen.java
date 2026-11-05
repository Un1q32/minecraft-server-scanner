package com.mcdbbrowser;

import java.util.function.IntConsumer;
import com.mcdbbrowser.McdbConfig.ButtonCorner;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.AbstractSliderButton;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.CommonComponents;
import net.minecraft.network.chat.Component;

public class SettingsScreen extends DropdownScreen {
	private static final int WIDGET_WIDTH = 240;
	private static final int ROW_HEIGHT = 20;
	private static final int ROW_SPACING = 24;

	private final Screen parent;
	private McdbConfig config = McdbConfig.get();
	private EditBox scannerDirBox;
	private EditBox pythonBox;

	public SettingsScreen(Screen parent) {
		super(Component.literal("MCDB Server Browser Settings"));
		this.parent = parent;
	}

	@Override
	protected void init() {
		int x = (this.width - WIDGET_WIDTH) / 2;
		int y = this.formTop();

		this.addRenderableWidget(new Dropdown<>(x, y, WIDGET_WIDTH, ROW_HEIGHT, "Button corner", ButtonCorner.values(), this.config.buttonCorner(),
			corner -> this.config = this.config.withButtonCorner(corner)));
		this.addRenderableWidget(new OffsetSlider(x, y + ROW_SPACING, "Horizontal offset", this.config.buttonOffsetX(),
			offset -> this.config = this.config.withButtonOffsetX(offset)));
		this.addRenderableWidget(new OffsetSlider(x, y + 2 * ROW_SPACING, "Vertical offset", this.config.buttonOffsetY(),
			offset -> this.config = this.config.withButtonOffsetY(offset)));

		this.scannerDirBox = new EditBox(this.font, x, y + 3 * ROW_SPACING, WIDGET_WIDTH, ROW_HEIGHT,
			Component.literal("Scanner directory"));
		this.scannerDirBox.setMaxLength(512);
		this.scannerDirBox.setHint(Component.literal("Scanner directory (contains mcscan.py)"));
		this.scannerDirBox.setValue(this.config.scannerDir());
		this.addRenderableWidget(this.scannerDirBox);

		this.pythonBox = new EditBox(this.font, x, y + 4 * ROW_SPACING, WIDGET_WIDTH, ROW_HEIGHT,
			Component.literal("Python command"));
		this.pythonBox.setMaxLength(128);
		this.pythonBox.setHint(Component.literal("Python command (python3)"));
		this.pythonBox.setValue(this.config.pythonCommand());
		this.addRenderableWidget(this.pythonBox);

		int halfWidth = (WIDGET_WIDTH - 4) / 2;
		this.addRenderableWidget(Button.builder(Component.literal("Reset"), button -> {
			this.config = McdbConfig.DEFAULT;
			this.rebuildWidgets();
		}).bounds(x, y + 6 * ROW_SPACING, halfWidth, ROW_HEIGHT).build());
		this.addRenderableWidget(Button.builder(CommonComponents.GUI_DONE, button -> this.onClose())
			.bounds(x + WIDGET_WIDTH - halfWidth, y + 6 * ROW_SPACING, halfWidth, ROW_HEIGHT).build());
	}

	private int formTop() {
		return Math.max(48, this.height / 2 - 3 * ROW_SPACING);
	}

	@Override
	protected void extractForeground(GuiGraphicsExtractor graphics) {
		graphics.centeredText(this.font, this.title, this.width / 2, 15, 0xFFFFFFFF);
		graphics.centeredText(this.font, "Where the Server DB button appears on the multiplayer screen",
			this.width / 2, Math.max(30, this.formTop() - 30), 0xFFA0A0A0);
		graphics.centeredText(this.font, "Rescan / whitelist / sync buttons run mcscan.py from the scanner directory",
			this.width / 2, Math.max(42, this.formTop() - 18), 0xFFA0A0A0);
	}

	@Override
	public void onClose() {
		if (this.scannerDirBox != null) {
			this.config = this.config
				.withScannerDir(this.scannerDirBox.getValue())
				.withPythonCommand(this.pythonBox.getValue());
		}
		McdbConfig.set(this.config);
		this.minecraft.gui.setScreen(this.parent);
	}

	private static class OffsetSlider extends AbstractSliderButton {
		private final String name;
		private final IntConsumer onChange;

		OffsetSlider(int x, int y, String name, int offset, IntConsumer onChange) {
			super(x, y, WIDGET_WIDTH, ROW_HEIGHT, Component.empty(), (double) offset / McdbConfig.MAX_OFFSET);
			this.name = name;
			this.onChange = onChange;
			this.updateMessage();
		}

		private int offset() {
			return (int) Math.round(this.value * McdbConfig.MAX_OFFSET);
		}

		@Override
		protected void updateMessage() {
			this.setMessage(Component.literal(this.name + ": " + this.offset() + " px"));
		}

		@Override
		protected void applyValue() {
			this.onChange.accept(this.offset());
		}
	}
}
