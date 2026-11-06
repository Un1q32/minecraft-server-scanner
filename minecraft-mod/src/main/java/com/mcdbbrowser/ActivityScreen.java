package com.mcdbbrowser;

import java.util.Locale;
import java.util.concurrent.CompletionException;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.CommonComponents;
import net.minecraft.network.chat.Component;
import org.jspecify.annotations.Nullable;

/** Full-screen sighting and player-activity charts for one server. */
public class ActivityScreen extends Screen {
	private static final int WHITE = 0xFFFFFFFF;
	private static final int GRAY = 0xFF808080;
	private static final int RED = 0xFFFF5555;
	private static final int MARGIN = 10;
	private static final int GAP = 4;
	private static final int FOOTER_HEIGHT = 50;

	private final Screen parent;
	private final String hostAndPort;
	private ServerDatabase.@Nullable ServerActivity activity;
	private boolean loading;
	private @Nullable String status;
	private int statusColor = GRAY;
	private @Nullable Button reloadButton;

	public ActivityScreen(Screen parent, String hostAndPort) {
		super(Component.literal("Activity: " + hostAndPort));
		this.parent = parent;
		this.hostAndPort = hostAndPort;
	}

	@Override
	protected void init() {
		int width = 100;
		int total = 2 * width + GAP;
		int x = (this.width - total) / 2;
		int y = this.height - 28;
		this.reloadButton = this.addRenderableWidget(Button.builder(
			Component.literal("Reload"), button -> this.load())
			.bounds(x, y, width, 20).build());
		this.addRenderableWidget(Button.builder(CommonComponents.GUI_BACK, button -> this.onClose())
			.bounds(x + width + GAP, y, width, 20).build());
		this.load();
	}

	private void load() {
		this.loading = true;
		this.activity = null;
		this.status = "Loading activity...";
		this.statusColor = GRAY;
		ServerDatabase.load(false, (downloaded, total) -> {
		}).thenCompose(ignored -> ServerDatabase.activity(this.hostAndPort))
			.whenComplete((loaded, throwable) -> this.minecraft.execute(() -> {
				this.loading = false;
				if (throwable != null) {
					Throwable cause = throwable instanceof CompletionException && throwable.getCause() != null
						? throwable.getCause() : throwable;
					McdbBrowserClient.LOGGER.error("Failed to load activity for {}", this.hostAndPort, cause);
					this.status = "Could not load activity: " + (cause.getMessage() == null
						? cause.getClass().getSimpleName() : cause.getMessage());
					this.statusColor = RED;
				} else {
					this.activity = loaded;
					this.status = null;
				}
			}));
	}

	@Override
	public void tick() {
		if (this.reloadButton != null) {
			this.reloadButton.active = !this.loading;
		}
	}

	@Override
	public void extractRenderState(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float a) {
		super.extractRenderState(graphics, mouseX, mouseY, a);
		graphics.centeredText(this.font, this.title, this.width / 2, 8, WHITE);

		int top = 30;
		int bottom = this.height - FOOTER_HEIGHT;
		if (this.loading) {
			ActivityCharts.drawMessage(graphics, this.font, MARGIN, top, this.width - 2 * MARGIN,
				Math.max(20, bottom - top), this.status == null ? "Loading activity..." : this.status, GRAY);
			return;
		}
		if (this.activity == null) {
			ActivityCharts.drawMessage(graphics, this.font, MARGIN, top, this.width - 2 * MARGIN,
				Math.max(20, bottom - top), this.status == null ? "No activity" : this.status, this.statusColor);
			return;
		}
		ActivityCharts.drawAll(graphics, this.font, MARGIN, top, this.width - 2 * MARGIN,
			Math.max(20, bottom - top), this.activity);

		int statusY = this.height - FOOTER_HEIGHT + 10;
		String text = String.format(Locale.ROOT, "%,d sightings • %,d players seen",
			this.activity.points().size(), this.activity.players().size());
		graphics.centeredText(this.font, text, this.width / 2, statusY, GRAY);
	}

	@Override
	public void onClose() {
		this.minecraft.gui.setScreen(this.parent);
	}
}
