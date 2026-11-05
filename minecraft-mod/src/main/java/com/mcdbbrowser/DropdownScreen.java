package com.mcdbbrowser;

import java.util.Optional;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.events.GuiEventListener;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.input.KeyEvent;
import net.minecraft.network.chat.Component;
import org.jspecify.annotations.Nullable;

/**
 * A screen hosting {@link Dropdown}s. While a menu is open the dropdown is
 * returned from getChildAt(), so ordinary vanilla mouse dispatch calls the
 * dropdown's own mouseClicked() for both the button and the menu rows.
 */
abstract class DropdownScreen extends Screen {
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
	public Optional<GuiEventListener> getChildAt(double x, double y) {
		// The open menu can overlap the server list and other widgets. Claim
		// every click while it is open; Dropdown.mouseClicked() decides whether
		// it was a row, the button, or an outside click that closes the menu.
		Dropdown<?> open = this.openDropdown();
		if (open != null) {
			return Optional.of(open);
		}
		return super.getChildAt(x, y);
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
