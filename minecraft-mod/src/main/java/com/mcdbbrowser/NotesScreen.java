package com.mcdbbrowser;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletionException;
import net.minecraft.ChatFormatting;
import net.minecraft.client.gui.Font;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.ObjectSelectionList;
import net.minecraft.client.gui.screens.ConfirmScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.input.KeyEvent;
import net.minecraft.client.input.MouseButtonEvent;
import net.minecraft.network.chat.CommonComponents;
import net.minecraft.network.chat.Component;
import org.jspecify.annotations.Nullable;

/** Viewer for the scanner's shared per-server notes. */
public class NotesScreen extends Screen {
	private static final int WHITE = 0xFFFFFFFF;
	private static final int GRAY = 0xFF808080;
	private static final int RED = 0xFFFF5555;
	private static final int GREEN = 0xFF55FF55;
	private static final int MARGIN = 10;
	private static final int ROW_HEIGHT = 20;
	private static final int LIST_TOP = 30;
	private static final int FOOTER_HEIGHT = 76;
	private static final int BUTTON_WIDTH = 90;
	private static final int GAP = 4;
	private static final long STATUS_MILLIS = 4000;

	private final Screen parent;
	private final String hostAndPort;
	private @Nullable List<NotesDatabase.Note> notes;
	private boolean loading;
	private boolean busy;
	private boolean syncPending;
	private @Nullable String status;
	private int statusColor = GRAY;
	private long statusExpiresAt;

	private NoteList list;
	private Button openButton;
	private Button deleteButton;
	private Button addButton;
	private Button syncButton;

	public NotesScreen(Screen parent, String hostAndPort) {
		super(Component.literal("Notes: " + hostAndPort));
		this.parent = parent;
		this.hostAndPort = hostAndPort;
	}

	@Override
	protected void init() {
		this.list = this.addRenderableWidget(new NoteList(
			this.width, this.height - FOOTER_HEIGHT - LIST_TOP, LIST_TOP));

		int count = 5;
		int buttonWidth = Math.max(70,
			Math.min(BUTTON_WIDTH, (this.width - 2 * MARGIN - (count - 1) * GAP) / count));
		int footerX = (this.width - (count * buttonWidth + (count - 1) * GAP)) / 2;
		int step = buttonWidth + GAP;
		int y = this.height - 28;

		this.addButton = this.addRenderableWidget(Button.builder(Component.literal("Add Note"),
			button -> this.openEditor(null))
			.bounds(footerX, y, buttonWidth, ROW_HEIGHT).build());
		this.openButton = this.addRenderableWidget(Button.builder(Component.literal("Open"),
			button -> this.openSelected())
			.bounds(footerX + step, y, buttonWidth, ROW_HEIGHT).build());
		this.deleteButton = this.addRenderableWidget(Button.builder(Component.literal("Delete"),
			button -> this.deleteSelected())
			.bounds(footerX + 2 * step, y, buttonWidth, ROW_HEIGHT).build());
		this.syncButton = this.addRenderableWidget(Button.builder(Component.literal("Sync"),
			button -> this.sync())
			.bounds(footerX + 3 * step, y, buttonWidth, ROW_HEIGHT).build());
		this.addRenderableWidget(Button.builder(CommonComponents.GUI_BACK, button -> this.onClose())
			.bounds(footerX + 4 * step, y, buttonWidth, ROW_HEIGHT).build());

		this.load();
	}

	private void load() {
		this.loading = true;
		NotesDatabase.list(this.hostAndPort).whenComplete((loaded, throwable) ->
			this.minecraft.execute(() -> {
				this.loading = false;
				if (throwable != null) {
					Throwable cause = throwable instanceof CompletionException && throwable.getCause() != null
						? throwable.getCause() : throwable;
					McdbBrowserClient.LOGGER.error("Failed to load notes for {}", this.hostAndPort, cause);
					this.notes = List.of();
					this.showStatus("Could not load notes: " + describe(cause), RED);
				} else {
					this.notes = loaded == null ? List.of() : loaded;
				}
				this.refreshList();
			}));
	}

	private void refreshList() {
		this.list.setNotes(this.notes == null ? List.of() : this.notes);
		this.updateButtonStates();
	}

	private void updateButtonStates() {
		boolean hasSelection = this.list.getSelected() != null;
		this.addButton.active = !this.busy;
		this.openButton.active = !this.busy && hasSelection;
		this.deleteButton.active = !this.busy && hasSelection;
		this.syncButton.active = !this.busy;
	}

	private void openSelected() {
		NoteList.Entry entry = this.list.getSelected();
		if (entry != null) {
			this.openEditor(entry.note);
		}
	}

	private void openEditor(NotesDatabase.@Nullable Note note) {
		this.minecraft.gui.setScreen(new NoteEditorScreen(this, this.hostAndPort, note));
	}

	private void deleteSelected() {
		NoteList.Entry entry = this.list.getSelected();
		if (entry == null) {
			return;
		}
		NotesDatabase.Note note = entry.note;
		this.minecraft.gui.setScreen(new ConfirmScreen(confirmed -> {
			this.minecraft.gui.setScreen(this);
			if (confirmed) {
				this.delete(note);
			}
		}, Component.literal("Delete this note?"),
			Component.literal("The note is removed for everyone on the next sync.")));
	}

	private void delete(NotesDatabase.Note note) {
		this.busy = true;
		this.showStatus("Deleting note...", GRAY);
		this.updateButtonStates();
		NotesDatabase.delete(note.id()).whenComplete((changed, throwable) ->
			this.minecraft.execute(() -> {
				this.busy = false;
				if (throwable != null) {
					this.showStatus("Could not delete note: " + describe(throwable), RED);
				} else if (Boolean.TRUE.equals(changed)) {
					this.showStatus("Note deleted. Syncing...", GREEN);
					this.load();
					this.sync();
					return;
				} else {
					this.showStatus("Note was already deleted", GRAY);
				}
				this.updateButtonStates();
			}));
	}

	/** Called by the editor after a note was added or replaced. */
	void noteSaved(String message) {
		this.showStatus(message, GREEN);
		this.load();
		this.sync();
	}

	private void sync() {
		if (this.busy) {
			this.syncPending = true;
			return;
		}
		this.busy = true;
		this.showStatus("Syncing notes...", GRAY);
		this.updateButtonStates();
		ScannerRunner.sync(line -> {
		}).whenComplete((result, throwable) -> this.minecraft.execute(() -> {
			this.busy = false;
			if (throwable != null) {
				this.showStatus("Saved locally; sync failed: " + describe(throwable), RED);
			} else if (result == null || !result.ok()) {
				this.showStatus("Saved locally; sync failed: "
					+ (result == null ? "unknown error" : result.message()), RED);
			} else {
				this.showStatus("Notes synced", GREEN);
				this.load();
			}
			this.updateButtonStates();
			if (this.syncPending) {
				this.syncPending = false;
				this.sync();
			}
		}));
	}

	private void showStatus(String text, int color) {
		this.status = text;
		this.statusColor = color;
		this.statusExpiresAt = System.currentTimeMillis() + STATUS_MILLIS;
	}

	private static String describe(Throwable throwable) {
		Throwable cause = throwable instanceof CompletionException && throwable.getCause() != null
			? throwable.getCause() : throwable;
		return cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage();
	}

	@Override
	public void tick() {
		if (this.status != null && System.currentTimeMillis() >= this.statusExpiresAt) {
			this.status = null;
		}
		this.updateButtonStates();
	}

	@Override
	public void extractRenderState(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float a) {
		super.extractRenderState(graphics, mouseX, mouseY, a);
		graphics.centeredText(this.font, this.title, this.width / 2, 8, WHITE);

		int statusY = this.height - FOOTER_HEIGHT + 10;
		if (this.status != null) {
			graphics.centeredText(this.font, this.status, this.width / 2, statusY, this.statusColor);
		} else if (this.loading) {
			graphics.centeredText(this.font, "Loading notes...", this.width / 2, statusY, GRAY);
		} else if (this.notes != null) {
			String count = this.notes.isEmpty()
				? "No notes for this server yet"
				: String.format(Locale.ROOT, "%,d note%s", this.notes.size(), this.notes.size() == 1 ? "" : "s");
			graphics.centeredText(this.font, count, this.width / 2, statusY, GRAY);
		}
	}

	@Override
	public void onClose() {
		this.minecraft.gui.setScreen(this.parent);
	}

	private class NoteList extends ObjectSelectionList<NoteList.Entry> {
		private static final int ENTRY_HEIGHT = 24;
		private static final int MAX_ROW_WIDTH = 560;
		private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
			.withZone(ZoneId.systemDefault());

		private @Nullable List<NotesDatabase.Note> notes = List.of();

		NoteList(int width, int height, int y) {
			super(NotesScreen.this.minecraft, width, height, y, ENTRY_HEIGHT);
		}

		void setNotes(List<NotesDatabase.Note> notes) {
			this.notes = notes;
			this.replaceEntries(notes.stream().map(Entry::new).toList());
		}

		@Override
		public int getRowWidth() {
			return Math.min(MAX_ROW_WIDTH, this.width - 4 * MARGIN);
		}

		class Entry extends ObjectSelectionList.Entry<Entry> {
			final NotesDatabase.Note note;
			private final String timestamp;
			private final String preview;

			Entry(NotesDatabase.Note note) {
				this.note = note;
				this.timestamp = TIME.format(Instant.ofEpochSecond((long) note.createdAt()));
				String first = note.text() == null ? "" : note.text().lines()
					.map(String::strip).filter(line -> !line.isEmpty()).findFirst().orElse("");
				this.preview = first.length() > 160 ? first.substring(0, 160) + "..." : first;
			}

			@Override
			public void extractContent(GuiGraphicsExtractor graphics, int mouseX, int mouseY, boolean hovered, float a) {
				Font font = NotesScreen.this.font;
				int left = this.getContentX();
				int top = this.getContentY();
				int right = this.getContentRight();
				int timeWidth = font.width(this.timestamp);
				graphics.text(font, this.timestamp, left, top + 4, GRAY);
				int textX = left + timeWidth + 8;
				graphics.text(font, font.plainSubstrByWidth(this.preview, Math.max(0, right - textX)),
					textX, top + 4, WHITE);
			}

			@Override
			public boolean mouseClicked(MouseButtonEvent event, boolean doubleClick) {
				if (doubleClick) {
					NotesScreen.this.openEditor(this.note);
				}
				return super.mouseClicked(event, doubleClick);
			}

			@Override
			public boolean keyPressed(KeyEvent event) {
				if (event.isSelection()) {
					NotesScreen.this.openEditor(this.note);
					return true;
				}
				return super.keyPressed(event);
			}

			@Override
			public Component getNarration() {
				return Component.literal(this.preview).withStyle(ChatFormatting.WHITE);
			}
		}
	}
}
