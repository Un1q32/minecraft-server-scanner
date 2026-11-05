package com.mcdbbrowser;

import java.util.List;
import java.util.function.Consumer;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.Font;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.AbstractButton;
import net.minecraft.client.gui.narration.NarrationElementOutput;
import net.minecraft.client.input.InputWithModifiers;
import net.minecraft.client.input.KeyEvent;
import net.minecraft.network.chat.Component;

/** A button showing the current value that opens a menu of all values. The menu itself is driven by {@link DropdownScreen}. */
final class Dropdown<T extends ServerDatabase.Labeled> extends AbstractButton {
	private static final int MENU_ROW_HEIGHT = 14;
	private static final int TEXT_INSET = 6;
	private static final int BACKGROUND = 0xF0101010;
	private static final int BORDER = 0xFFA0A0A0;
	private static final int HIGHLIGHT = 0x60FFFFFF;
	private static final int WHITE = 0xFFFFFFFF;
	private static final int SELECTED_TEXT = 0xFFFFFF55;

	private final String name;
	private final List<T> values;
	private final Consumer<T> onChange;
	private T value;
	private boolean open;
	private int highlighted;
	private int lastMouseX = -1;
	private int lastMouseY = -1;

	Dropdown(int x, int y, int width, int height, String name, T[] values, T initial, Consumer<T> onChange) {
		super(x, y, width, height, Component.empty());
		this.name = name;
		this.values = List.of(values);
		this.onChange = onChange;
		this.value = initial;
		this.updateMessage();
	}

	private void updateMessage() {
		this.setMessage(Component.literal(this.name + ": " + this.value.label() + " ▼"));
	}

	boolean isOpen() {
		return this.open;
	}

	@Override
	public void onPress(InputWithModifiers input) {
		this.open = true;
		this.highlighted = this.values.indexOf(this.value);
	}

	@Override
	protected void extractContents(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float a) {
		this.extractDefaultSprite(graphics);
		this.extractDefaultLabel(graphics.textRendererForWidget(this, GuiGraphicsExtractor.HoveredTextEffects.NONE));
	}

	@Override
	protected void updateWidgetNarration(NarrationElementOutput output) {
		this.defaultButtonNarrationText(output);
	}

	private int menuHeight() {
		return this.values.size() * MENU_ROW_HEIGHT;
	}

	/** Opens downward unless that would run off the bottom of the screen. */
	private int menuTop() {
		int below = this.getY() + this.getHeight();
		int screenHeight = Minecraft.getInstance().getWindow().getGuiScaledHeight();
		boolean fitsBelow = below + this.menuHeight() <= screenHeight;
		return fitsBelow || this.getY() < this.menuHeight() ? below : this.getY() - this.menuHeight();
	}

	private int rowAt(double x, double y) {
		int top = this.menuTop();
		if (x < this.getX() || x >= this.getX() + this.getWidth() || y < top || y >= top + this.menuHeight()) {
			return -1;
		}
		return (int) ((y - top) / MENU_ROW_HEIGHT);
	}

	void extractMenu(GuiGraphicsExtractor graphics, int mouseX, int mouseY) {
		// Only a moving mouse takes the highlight, so a resting cursor doesn't fight the arrow keys
		if (mouseX != this.lastMouseX || mouseY != this.lastMouseY) {
			this.lastMouseX = mouseX;
			this.lastMouseY = mouseY;
			int row = this.rowAt(mouseX, mouseY);
			if (row >= 0) {
				this.highlighted = row;
			}
		}

		Font font = Minecraft.getInstance().font;
		int left = this.getX();
		int top = this.menuTop();
		int width = this.getWidth();

		graphics.nextStratum();
		graphics.fill(left, top, left + width, top + this.menuHeight(), BACKGROUND);
		for (int i = 0; i < this.values.size(); i++) {
			T rowValue = this.values.get(i);
			int rowTop = top + i * MENU_ROW_HEIGHT;
			if (i == this.highlighted) {
				graphics.fill(left, rowTop, left + width, rowTop + MENU_ROW_HEIGHT, HIGHLIGHT);
			}
			String label = font.plainSubstrByWidth(rowValue.label(), width - 2 * TEXT_INSET);
			graphics.text(font, label, left + TEXT_INSET, rowTop + 3, rowValue == this.value ? SELECTED_TEXT : WHITE);
		}
		graphics.outline(left, top, width, this.menuHeight(), BORDER);
	}

	/** Any click closes the menu; only a left click on a row picks that row. */
	void menuClicked(double x, double y, boolean leftButton) {
		int row = this.rowAt(x, y);
		this.open = false;
		if (row >= 0 && leftButton) {
			this.playDownSound(Minecraft.getInstance().getSoundManager());
			this.select(this.values.get(row));
		}
	}

	void menuKeyPressed(KeyEvent event) {
		if (event.isEscape()) {
			this.open = false;
		} else if (event.isUp()) {
			this.highlighted = Math.floorMod(this.highlighted - 1, this.values.size());
		} else if (event.isDown()) {
			this.highlighted = Math.floorMod(this.highlighted + 1, this.values.size());
		} else if (event.isSelection()) {
			this.open = false;
			this.playDownSound(Minecraft.getInstance().getSoundManager());
			this.select(this.values.get(this.highlighted));
		}
	}

	private void select(T newValue) {
		if (newValue != this.value) {
			this.value = newValue;
			this.updateMessage();
			this.onChange.accept(newValue);
		}
	}
}
