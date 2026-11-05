package com.mcdbbrowser;

import java.lang.ref.WeakReference;
import java.util.Locale;
import net.minecraft.client.Minecraft;
import net.minecraft.network.chat.Component;
import org.jspecify.annotations.Nullable;

/**
 * Fills in a missing whitelist verdict from a real client join.
 *
 * The probe used by the scanner opens its own login connection, but a join the
 * user is already making answers the same question: getting into the world
 * means the server is open to us, and a whitelist kick means it is not. The
 * result is written back to the local cache, the scanner DB and the shared DB.
 */
public final class WhitelistAutoUpdate {
	private static final long PENDING_MILLIS = 120_000L;
	private static final int MAX_DETAIL_CHARS = 160;

	private static volatile @Nullable Pending pending;
	private static WeakReference<ServerBrowserScreen> browser = new WeakReference<>(null);

	private WhitelistAutoUpdate() {
	}

	/** Called from the join mixin before the connection attempt starts. */
	public static void track(String address) {
		if (address != null && !address.isBlank()) {
			pending = new Pending(address, System.currentTimeMillis());
		}
	}

	/** The browser screen is the one that can repaint rows immediately. */
	static void attach(ServerBrowserScreen screen) {
		browser = new WeakReference<>(screen);
	}

	/** The client reached the world, so the server is not whitelisting us. */
	public static void onJoined() {
		Pending attempt = takePending();
		if (attempt != null) {
			evaluate(attempt.address, "Not Whitelisted: joined successfully");
		}
	}

	/** The login/world connection was rejected; keep whitelist rejections only. */
	public static void onDisconnected(@Nullable Component reason) {
		Pending attempt = takePending();
		if (attempt == null) {
			return;
		}
		String text = reason == null ? "" : reason.getString();
		if (mentionsWhitelist(text)) {
			evaluate(attempt.address, "Whitelisted: " + shorten(text));
		}
	}

	private static boolean mentionsWhitelist(String text) {
		String lower = text.toLowerCase(Locale.ROOT);
		return lower.contains("whitelist") || lower.contains("white list") || lower.contains("white-list");
	}

	private static void evaluate(String address, String label) {
		// Only fill in rows that actually lack information. An explicit recheck
		// remains authoritative when it already produced a verdict.
		ServerDatabase.whitelistOf(address).whenComplete((existing, error) -> {
			if (error != null || existing == null || !isUnknown(existing)) {
				return;
			}
			apply(address, label);
		});
	}

	private static boolean isUnknown(@Nullable String value) {
		String text = value == null ? "" : value.strip();
		return text.isEmpty() || text.regionMatches(true, 0, "Unknown", 0, "Unknown".length());
	}

	private static void apply(String address, String label) {
		Minecraft client = Minecraft.getInstance();
		client.execute(() -> {
			ServerBrowserScreen screen = browser.get();
			if (screen != null) {
				screen.applyWhitelist(address, label);
			} else {
				ServerDatabase.setWhitelist(address, label);
			}
		});
		ScannerRunner.setWhitelist(address, label, line -> {
		}).whenComplete((result, error) -> {
			if (error != null) {
				McdbBrowserClient.LOGGER.warn("Could not publish the whitelist for {}", address, error);
			} else if (result == null || !result.ok()) {
				McdbBrowserClient.LOGGER.warn("Could not publish the whitelist for {}: {}",
					address, result == null ? "no result" : result.message());
			}
		});
	}

	private static @Nullable Pending takePending() {
		Pending attempt = pending;
		pending = null;
		if (attempt == null || System.currentTimeMillis() - attempt.startedAtMillis > PENDING_MILLIS) {
			return null;
		}
		return attempt;
	}

	private static String shorten(String text) {
		String detail = text == null ? "" : text.strip();
		return detail.length() <= MAX_DETAIL_CHARS
			? detail : detail.substring(0, MAX_DETAIL_CHARS - 3) + "...";
	}

	private record Pending(String address, long startedAtMillis) {
	}
}
