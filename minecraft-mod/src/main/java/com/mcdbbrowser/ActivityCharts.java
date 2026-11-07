package com.mcdbbrowser;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import net.minecraft.client.gui.Font;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.network.chat.Component;
import net.minecraft.util.FormattedCharSequence;

/** Shared sighting/player-activity chart rendering for the list pane and full screen. */
final class ActivityCharts {
	private static final int WHITE = 0xFFFFFFFF;
	private static final int GRAY = 0xFF808080;
	private static final int DARK_GRAY = 0xFF606060;
	private static final int GAP = 4;
	private static final int MAX_PLAYER_ROWS = 10;
	private static final int MAX_DOTS_PER_PLAYER = 200;
	private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("MM/dd HH:mm")
		.withZone(ZoneId.systemDefault());
	private static final int[] COLORS = {
		0xFF6FA8DC, 0xFF93C47D, 0xFFE6B85C, 0xFFE07B8F, 0xFFB4A7D6,
		0xFF76A5AF, 0xFFF0A35E, 0xFFC3D36C, 0xFFD98CC4, 0xFF8FB8E8,
	};

	private ActivityCharts() {
	}

	static void drawAll(GuiGraphicsExtractor graphics, Font font, int x, int y, int w, int h,
	                    ServerDatabase.ServerActivity data, double viewStart, double viewEnd) {
		if (h < 54) {
			drawMessage(graphics, font, x, y, w, h, "Not enough room for activity", DARK_GRAY);
			return;
		}
		int minSight = 38;
		int minPlayer = 30;
		if (h < minSight + minPlayer + GAP) {
			drawSightings(graphics, font, x, y, w, h, data.points(), viewStart, viewEnd);
			return;
		}
		int sightHeight = Math.min(h - minPlayer - GAP, Math.max(minSight, h * 44 / 100));
		int playerY = y + sightHeight + GAP;
		int playerHeight = y + h - playerY;
		drawSightings(graphics, font, x, y, w, sightHeight, data.points(), viewStart, viewEnd);
		drawPlayers(graphics, font, x, playerY, w, playerHeight, data.players(), viewStart, viewEnd);
	}

	static int plotLeft(int x) {
		return x + 34;
	}

	static int plotRight(int x, int w) {
		return x + w - 8;
	}

	static void drawMessage(GuiGraphicsExtractor graphics, Font font, int x, int y, int w, int h,
	                        String message, int color) {
		graphics.fill(x, y, x + w, y + h, 0x30000000);
		graphics.outline(x, y, w, h, 0x50808080);
		graphics.centeredText(font, message, x + w / 2, y + h / 2 - 4, color);
	}

	private static void drawSightings(GuiGraphicsExtractor graphics, Font font, int x, int y, int w, int h,
	                                  List<ServerDatabase.HistoryPoint> points, double t0, double t1) {
		int peak = 1;
		boolean counted = false;
		int visible = 0;
		for (ServerDatabase.HistoryPoint point : points) {
			if (point.seenAt() < t0 || point.seenAt() > t1) {
				continue;
			}
			visible++;
			if (point.playersOnline() != null) {
				peak = Math.max(peak, point.playersOnline());
				counted = true;
			}
		}
		if (!counted) {
			for (ServerDatabase.HistoryPoint point : points) {
				if (point.seenAt() >= t0 && point.seenAt() <= t1
						&& point.maxPlayers() != null) {
					peak = Math.max(peak, point.maxPlayers());
				}
			}
		}
		panel(graphics, font, x, y, w, h, String.format(Locale.ROOT,
			"SIGHTINGS %,d • PEAK %d", points.size(), peak));

		int left = x + 34;
		int right = x + w - 8;
		int top = y + 15;
		int bottom = y + h - 16;
		if (right <= left || bottom <= top) {
			graphics.centeredText(font, "No room for chart", (x + x + w) / 2, y + h / 2, DARK_GRAY);
			return;
		}
		for (int i = 0; i <= 2; i++) {
			int value = peak * i / 2;
			int gy = bottom - (bottom - top) * i / 2;
			graphics.fill(left, gy, right + 1, gy + 1, 0x40808080);
			String label = Integer.toString(value);
			graphics.text(font, label, left - font.width(label) - 4, gy - 4, GRAY);
		}
		graphics.text(font, TIME.format(Instant.ofEpochSecond((long) t0)), left, bottom + 6, DARK_GRAY);
		String end = t1 > t0 ? TIME.format(Instant.ofEpochSecond((long) t1)) : "";
		if (!end.isEmpty()) {
			graphics.text(font, end, right - font.width(end), bottom + 6, DARK_GRAY);
		}

		// Keep the span fractional: truncating it to whole seconds made the
		// last point of a short (sub-2s) view round past the array bound.
		double span = Math.max(1.0, t1 - t0);
		int pixels = Math.max(1, right - left);
		int[] yAt = new int[pixels + 1];
		boolean[] hasPoint = new boolean[pixels + 1];
		boolean[] tick = new boolean[pixels + 1];
		for (ServerDatabase.HistoryPoint point : points) {
			if (point.seenAt() < t0 || point.seenAt() > t1) {
				continue;
			}
			int px = left + (int) Math.round((point.seenAt() - t0) * pixels / span);
			px = Math.max(left, Math.min(right, px));
			tick[px - left] = true;
			if (point.playersOnline() == null) {
				continue;
			}
			int py = bottom - (int) Math.round(Math.min(1.0,
				(double) point.playersOnline() / peak) * (bottom - top));
			int index = px - left;
			if (!hasPoint[index] || py < yAt[index]) {
				yAt[index] = py;
				hasPoint[index] = true;
			}
		}
		int lastX = -1;
		int lastY = -1;
		for (int i = 0; i <= pixels; i++) {
			if (!hasPoint[i]) {
				continue;
			}
			int px = left + i;
			int py = yAt[i];
			if (lastX >= 0) {
				drawLine(graphics, lastX, lastY, px, py, COLORS[0]);
			}
			graphics.fill(px, py, px + 2, py + 2, COLORS[0]);
			lastX = px;
			lastY = py;
		}
		for (int i = 0; i <= pixels; i++) {
			if (tick[i]) {
				graphics.fill(left + i, bottom + 1, left + i + 1, bottom + 4, 0xFF7AA6CC);
			}
		}
		if (visible == 0) {
			graphics.centeredText(font, "No sightings in this window", (left + right) / 2,
				(top + bottom) / 2, DARK_GRAY);
		} else if (!counted) {
			graphics.centeredText(font, "No player counts recorded", (left + right) / 2,
				(top + bottom) / 2, DARK_GRAY);
		}
	}

	private static void drawPlayers(GuiGraphicsExtractor graphics, Font font, int x, int y, int w, int h,
	                                List<ServerDatabase.PlayerActivity> players, double t0, double t1) {
		List<ServerDatabase.PlayerActivity> sorted = new ArrayList<>(players);
		sorted.sort(Comparator
			.comparingInt((ServerDatabase.PlayerActivity player) -> player.times().size()).reversed()
			.thenComparing(ServerDatabase.PlayerActivity::name, String.CASE_INSENSITIVE_ORDER));
		panel(graphics, font, x, y, w, h, String.format(Locale.ROOT,
			"PLAYER ACTIVITY • %,d SEEN", players.size()));

		int left = x + 92;
		int right = x + w - 8;
		int top = y + 15;
		int bottom = y + h - 4;
		int rowHeight = 12;
		int maxRows = Math.max(1, (bottom - top) / rowHeight);
		int shown = Math.min(sorted.size(), Math.min(MAX_PLAYER_ROWS, maxRows));
		if (shown == 0 || right <= left || bottom <= top) {
			graphics.centeredText(font, players.isEmpty() ? "No player activity recorded" : "No room for chart",
				(x + x + w) / 2, y + h / 2, DARK_GRAY);
			return;
		}
		double span = Math.max(1.0, t1 - t0);
		int pixels = Math.max(1, right - left);
		for (int row = 0; row < shown; row++) {
			ServerDatabase.PlayerActivity player = sorted.get(row);
			int centerY = top + row * rowHeight + rowHeight / 2;
			graphics.fill(left, centerY, right + 1, centerY + 1, 0x30808080);
			String name = player.name();
			if (name.length() > 14) {
				name = name.substring(0, 13) + "…";
			}
			graphics.text(font, name, x + 4, centerY - 4, WHITE);
			List<Double> times = player.times();
			int step = Math.max(1, times.size() / MAX_DOTS_PER_PLAYER);
			for (int i = 0; i < times.size(); i += step) {
				double time = times.get(i);
				if (time < t0 || time > t1) {
					continue;
				}
				int px = left + (int) Math.round((time - t0) * pixels / span);
				px = Math.max(left, Math.min(right, px));
				graphics.fill(px - 1, centerY - 1, px + 2, centerY + 2, COLORS[row % COLORS.length]);
			}
		}
		if (sorted.size() > shown) {
			graphics.text(font, "+" + (sorted.size() - shown) + " more player(s)",
				x + 4, top + shown * rowHeight, DARK_GRAY);
		}
	}

	/** Notes for the selected server, shown under the charts in the browser pane. */
	static void drawNotes(GuiGraphicsExtractor graphics, Font font, int x, int y, int w, int h,
	                      List<NotesDatabase.Note> notes) {
		if (notes.isEmpty() || h < 20) {
			return;
		}
		NotesDatabase.Note newest = notes.getLast();
		String stamp = TIME.format(Instant.ofEpochSecond((long) newest.createdAt()));
		panel(graphics, font, x, y, w, h, String.format(Locale.ROOT,
			"NOTES • %,d • %s", notes.size(), stamp));

		int textX = x + 4;
		int textWidth = Math.max(20, w - 8);
		int lineHeight = font.lineHeight + 1;
		int top = y + 14;
		int maxLines = Math.max(0, (y + h - 3 - top) / lineHeight);
		if (maxLines == 0) {
			return;
		}
		List<FormattedCharSequence> lines = new ArrayList<>();
		for (int i = notes.size() - 1; i >= 0; i--) {
			String body = notes.get(i).text();
			if (body == null) {
				continue;
			}
			for (String raw : body.replace('\r', ' ').split("\n")) {
				String line = raw.strip();
				if (line.isEmpty()) {
					if (!lines.isEmpty()) {
						lines.add(FormattedCharSequence.EMPTY);
					}
					continue;
				}
				lines.addAll(font.split(Component.literal(line), textWidth));
			}
			if (i > 0) {
				lines.add(FormattedCharSequence.EMPTY);
			}
		}
		boolean truncated = lines.size() > maxLines;
		int shown = truncated && maxLines > 1 ? maxLines - 1 : Math.min(lines.size(), maxLines);
		for (int i = 0; i < shown; i++) {
			graphics.text(font, lines.get(i), textX, top + i * lineHeight,
				i == 0 ? WHITE : 0xFFD0D0D0);
		}
		if (truncated && shown < maxLines) {
			graphics.text(font, "+" + (lines.size() - shown) + " more line(s) — click for all notes",
				textX, top + shown * lineHeight, DARK_GRAY);
		}
	}

	private static void panel(GuiGraphicsExtractor graphics, Font font, int x, int y, int w, int h, String title) {
		graphics.fill(x, y, x + w, y + h, 0x30000000);
		graphics.outline(x, y, w, h, 0x50808080);
		graphics.text(font, title, x + 4, y + 3, WHITE);
	}

	private static void drawLine(GuiGraphicsExtractor graphics, int x1, int y1, int x2, int y2, int color) {
		int dx = Math.abs(x2 - x1);
		int dy = Math.abs(y2 - y1);
		int sx = x1 < x2 ? 1 : -1;
		int sy = y1 < y2 ? 1 : -1;
		int error = dx - dy;
		while (true) {
			graphics.fill(x1, y1, x1 + 1, y1 + 1, color);
			if (x1 == x2 && y1 == y2) {
				return;
			}
			int twice = 2 * error;
			if (twice > -dy) {
				error -= dy;
				x1 += sx;
			}
			if (twice < dx) {
				error += dx;
				y1 += sy;
			}
		}
	}

	static double[] fullRange(List<ServerDatabase.HistoryPoint> points,
	                          List<ServerDatabase.PlayerActivity> players) {
		double lo = 0;
		double hi = 0;
		for (ServerDatabase.HistoryPoint point : points) {
			double t = point.seenAt();
			if (t <= 0) {
				continue;
			}
			if (lo == 0 || t < lo) {
				lo = t;
			}
			hi = Math.max(hi, t);
		}
		for (ServerDatabase.PlayerActivity player : players) {
			for (double t : player.times()) {
				if (t <= 0) {
					continue;
				}
				if (lo == 0 || t < lo) {
					lo = t;
				}
				hi = Math.max(hi, t);
			}
		}
		if (lo == 0) {
			return new double[] {0, 0};
		}
		if (hi <= lo) {
			hi = lo + 3600;
		}
		return new double[] {lo, hi};
	}
}
