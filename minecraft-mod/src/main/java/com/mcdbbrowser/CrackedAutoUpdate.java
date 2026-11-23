package com.mcdbbrowser;

import java.lang.ref.WeakReference;
import net.minecraft.client.Minecraft;

/**
 * Fills in the cracked/online verdict from a real client join.
 *
 * The client sees an Encryption Request only when the server requires Mojang
 * authentication. A join that reaches the world without one therefore proves
 * the server accepted an offline-mode login; one with it proves online mode.
 */
public final class CrackedAutoUpdate {
	private static final long PENDING_MILLIS = 120_000L;

	private static volatile Pending pending;
	private static WeakReference<ServerBrowserScreen> browser = new WeakReference<>(null);

	private CrackedAutoUpdate() {
	}

	/** Called from the join mixin before the connection attempt starts. */
	public static void track(String address) {
		if (address != null && !address.isBlank()) {
			pending = new Pending(address, System.currentTimeMillis(), false);
		}
	}

	/** The browser screen is the one that can repaint rows immediately. */
	static void attach(ServerBrowserScreen screen) {
		browser = new WeakReference<>(screen);
	}

	/** The server sent an Encryption Request, so it is online-mode. */
	public static void onEncryptionRequest() {
		Pending attempt = pending;
		if (attempt != null && !attempt.encrypted) {
			pending = new Pending(attempt.address, attempt.startedAtMillis, true);
		}
	}

	/** The client reached the world; verdict is the presence of encryption. */
	public static void onJoined() {
		Pending attempt = pending;
		pending = null;
		if (attempt == null
				|| System.currentTimeMillis() - attempt.startedAtMillis > PENDING_MILLIS) {
			return;
		}
		apply(attempt.address, attempt.encrypted ? "No" : "Yes");
	}

	private static void apply(String address, String label) {
		boolean cracked = "Yes".equals(label);
		Minecraft client = Minecraft.getInstance();
		client.execute(() -> {
			ServerBrowserScreen screen = browser.get();
			if (screen != null) {
				screen.applyCracked(address, cracked);
			} else {
				ServerDatabase.setCracked(address, cracked);
			}
		});
		ScannerRunner.setCracked(address, label, line -> {
		}).whenComplete((result, error) -> {
			if (error != null) {
				McdbBrowserClient.LOGGER.warn("Could not publish the cracked verdict for {}", address, error);
			} else if (result == null || !result.ok()) {
				McdbBrowserClient.LOGGER.warn("Could not publish the cracked verdict for {}: {}",
					address, result == null ? "no result" : result.message());
			}
		});
	}

	private record Pending(String address, long startedAtMillis, boolean encrypted) {
	}
}
