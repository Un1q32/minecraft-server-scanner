package com.mcdbbrowser;

import java.util.concurrent.CompletionException;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.MultiLineEditBox;
import net.minecraft.client.gui.screens.ConfirmScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.CommonComponents;
import net.minecraft.network.chat.Component;
import org.jspecify.annotations.Nullable;

/** Full-size editor for a new note, or for replacing an existing one. */
public class NoteEditorScreen extends Screen {
	private static final int WHITE = 0xFFFFFFFF;
	private static final int GRAY = 0xFF808080;
	private static final int RED = 0xFFFF5555;
	private static final int GREEN = 0xFF55FF55;
	private static final int MARGIN = 10;
	private static final int ROW_HEIGHT = 20;
	private static final int TOP = 44;
	private static final int FOOTER_HEIGHT = 70;
	private static final int BUTTON_WIDTH = 120;
	private static final int GAP = 4;

	private final Screen parent;
	private final String hostAndPort;
	private final NotesDatabase.@Nullable Note existing;
	private MultiLineEditBox editor;
	private Button saveButton;
	private boolean busy;
	private @Nullable String status;
	private int statusColor = GRAY;

	public NoteEditorScreen(Screen parent, String hostAndPort, NotesDatabase.@Nullable Note existing) {
		super(Component.literal(existing == null ? "New note: " + hostAndPort : "Edit note: " + hostAndPort));
		this.parent = parent;
		this.hostAndPort = hostAndPort;
		this.existing = existing;
	}

	@Override
	protected void init() {
		this.editor = this.addRenderableWidget(MultiLineEditBox.builder()
			.setX(MARGIN)
			.setY(TOP)
			.setPlaceholder(Component.literal("Write a note..."))
			.setShowBackground(true)
			.build(this.font, this.width - 2 * MARGIN, this.height - TOP - FOOTER_HEIGHT,
				Component.literal("Note")));
		this.editor.setCharacterLimit(NotesDatabase.MAX_NOTE_CHARS);
		this.editor.setValue(this.existing == null ? "" : this.existing.text());
		this.editor.setValueListener(value -> this.updateButtonStates());

		int total = 2 * BUTTON_WIDTH + GAP;
		int x = (this.width - total) / 2;
		int y = this.height - 28;
		this.saveButton = this.addRenderableWidget(Button.builder(
			Component.literal(this.existing == null ? "Add Note" : "Save Replacement"),
			button -> this.requestSave())
			.bounds(x, y, BUTTON_WIDTH, ROW_HEIGHT).build());
		this.addRenderableWidget(Button.builder(CommonComponents.GUI_CANCEL, button -> this.onClose())
			.bounds(x + BUTTON_WIDTH + GAP, y, BUTTON_WIDTH, ROW_HEIGHT).build());

		this.setInitialFocus(this.editor);
		this.updateButtonStates();
	}

	private void updateButtonStates() {
		if (this.saveButton != null && this.editor != null) {
			this.saveButton.active = !this.busy && !this.editor.getValue().isBlank();
		}
	}

	private void requestSave() {
		String body = this.editor.getValue().strip();
		if (body.isEmpty()) {
			this.showStatus("Write something first", RED);
			return;
		}
		if (this.existing != null && body.equals(this.existing.text().strip())) {
			this.onClose();
			return;
		}
		if (this.existing == null) {
			this.save(body);
			return;
		}

		this.minecraft.gui.setScreen(new ConfirmScreen(confirmed -> {
			this.minecraft.gui.setScreen(this);
			if (confirmed) {
				this.save(body);
			}
		}, Component.literal("Replace this note?"),
			Component.literal("Notes are write-once on the shared DB. The old note will be deleted and a new one added.")));
	}

	private void save(String body) {
		this.busy = true;
		this.showStatus("Saving...", GRAY);
		this.updateButtonStates();
		var future = this.existing == null
			? NotesDatabase.add(this.hostAndPort, body)
			: NotesDatabase.replace(this.existing.id(), this.hostAndPort, body);
		future.whenComplete((saved, throwable) -> this.minecraft.execute(() -> {
			this.busy = false;
			if (throwable != null) {
				this.showStatus("Could not save note: " + describe(throwable), RED);
				this.updateButtonStates();
			} else {
				if (this.parent instanceof NotesScreen notesScreen) {
					notesScreen.noteSaved(this.existing == null ? "Note added" : "Note replaced");
				}
				this.minecraft.gui.setScreen(this.parent);
			}
		}));
	}

	private void showStatus(String text, int color) {
		this.status = text;
		this.statusColor = color;
	}

	private static String describe(Throwable throwable) {
		Throwable cause = throwable instanceof CompletionException && throwable.getCause() != null
			? throwable.getCause() : throwable;
		return cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage();
	}

	@Override
	public void tick() {
		this.updateButtonStates();
	}

	@Override
	public void extractRenderState(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float a) {
		super.extractRenderState(graphics, mouseX, mouseY, a);
		graphics.centeredText(this.font, this.title, this.width / 2, 8, WHITE);
		String hint = this.existing == null
			? "Shared with everyone after syncing."
			: "Write-once note: saving deletes this one and creates a replacement.";
		graphics.centeredText(this.font, hint, this.width / 2, 22, GRAY);
		if (this.status != null) {
			graphics.centeredText(this.font, this.status, this.width / 2,
				this.height - FOOTER_HEIGHT + 10, this.statusColor);
		}
	}

	@Override
	public void onClose() {
		this.minecraft.gui.setScreen(this.parent);
	}
}
