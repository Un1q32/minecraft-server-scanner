package com.mcdbbrowser;

import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.events.GuiEventListener;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.input.KeyEvent;
import net.minecraft.client.input.MouseButtonEvent;
import net.minecraft.network.chat.Component;
import org.jspecify.annotations.Nullable;

/** A screen hosting {@link Dropdown}s. While a menu is open it draws on top of everything and takes all input. */
abstract class DropdownScreen extends Screen {
	private static final int LEFT_BUTTON = 0;
	private static final int NO_MOUSE = -1;

	protected DropdownScreen(Component title) {
		super(title);
	}

	/** Draws whatever the screen shows besides its widgets. Open menus are drawn over this. */
	protected abstract void extractForeground(GuiGraphicsExtractor graphics);

	private @Nullable Dropdown<?> openDropdown() {
		for (GuiEventListener child : this.children()) {
			if (child instanceof Dropdown<?> dropdown && dropdown.isOpen()) {
				return dropdown;
			}
		}
		return null;
	}

	@Override
	public final void extractRenderState(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float a) {
		Dropdown<?> open = this.openDropdown();
		// Widgets under an open menu are drawn without the mouse so they don't highlight or show tooltips through it
		super.extractRenderState(graphics, open == null ? mouseX : NO_MOUSE, open == null ? mouseY : NO_MOUSE, a);
		this.extractForeground(graphics);
		if (open != null) {
			open.extractMenu(graphics, mouseX, mouseY);
		}
	}

	@Override
	public boolean mouseClicked(MouseButtonEvent event, boolean doubleClick) {
		Dropdown<?> open = this.openDropdown();
		if (open == null) {
			return super.mouseClicked(event, doubleClick);
		}
		open.menuClicked(event.x(), event.y(), event.button() == LEFT_BUTTON);
		return true;
	}

	@Override
	public boolean mouseScrolled(double x, double y, double scrollX, double scrollY) {
		return this.openDropdown() != null || super.mouseScrolled(x, y, scrollX, scrollY);
	}

	@Override
	public boolean keyPressed(KeyEvent event) {
		Dropdown<?> open = this.openDropdown();
		if (open == null) {
			return super.keyPressed(event);
		}
		open.menuKeyPressed(event);
		return true;
	}
}
