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
	                    ServerDatabase.ServerActivity data) {
		double[] range = timeRange(data.points(), data.players());
		int sightHeight = Math.max(44, h * 44 / 100);
		int playerY = y + sightHeight + GAP;
		int playerHeight = Math.max(38, y + h - playerY);
		drawSightings(graphics, font, x, y, w, sightHeight, data.points(), range[0], range[1]);
		drawPlayers(graphics, font, x, playerY, w, playerHeight, data.players(), range[0], range[1]);
	}

	static void drawMessage(GuiGraphicsExtractor graphics, Font font, int x, int y, int w, int h,
	                        String message, int color) {
		graphics.fill(x, y, x + w, y + h, 0x30000000);
		graphics.outline(x, y, x + w, y + h, 0x50808080);
		graphics.centeredText(font, message, x + w / 2, y + h / 2 - 4, color);
	}

	private static void drawSightings(GuiGraphicsExtractor graphics, Font font, int x, int y, int w, int h,
	                                  List<ServerDatabase.HistoryPoint> points, double t0, double t1) {
		int peak = 1;
		boolean counted = false;
		for (ServerDatabase.HistoryPoint point : points) {
			if (point.playersOnline() != null) {
				peak = Math.max(peak, point.playersOnline());
				counted = true;
			}
		}
		if (!counted) {
			for (ServerDatabase.HistoryPoint point : points) {
				if (point.maxPlayers() != null) {
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

		int span = Math.max(1, (int) (t1 - t0));
		int pixels = Math.max(1, right - left);
		int[] yAt = new int[pixels + 1];
		boolean[] hasPoint = new boolean[pixels + 1];
		boolean[] tick = new boolean[pixels + 1];
		for (ServerDatabase.HistoryPoint point : points) {
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
		if (!counted) {
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
		int span = Math.max(1, (int) (t1 - t0));
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
				int px = left + (int) Math.round((times.get(i) - t0) * pixels / span);
				px = Math.max(left, Math.min(right, px));
				graphics.fill(px - 1, centerY - 1, px + 2, centerY + 2, COLORS[row % COLORS.length]);
			}
		}
		if (sorted.size() > shown) {
			graphics.text(font, "+" + (sorted.size() - shown) + " more player(s)",
				x + 4, top + shown * rowHeight, DARK_GRAY);
		}
	}

	private static void panel(GuiGraphicsExtractor graphics, Font font, int x, int y, int w, int h, String title) {
		graphics.fill(x, y, x + w, y + h, 0x30000000);
		graphics.outline(x, y, x + w, y + h, 0x50808080);
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

	private static double[] timeRange(List<ServerDatabase.HistoryPoint> points,
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
