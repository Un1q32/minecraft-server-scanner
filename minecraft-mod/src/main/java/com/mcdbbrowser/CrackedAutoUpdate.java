package com.mcdbbrowser;

import io.netty.channel.Channel;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.client.multiplayer.ClientPacketListener;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.network.Connection;
import org.jspecify.annotations.Nullable;

/**
 * Fills in the cracked/online verdict from a real client join.
 *
 * The client's connection pipeline has {@code decrypt}/{@code encrypt}
 * handlers only when the server requested Mojang authentication. A successful
 * join with those handlers is online mode; without them the server accepted an
 * offline-mode login.
 */
public final class CrackedAutoUpdate {
	private static WeakReference<ServerBrowserScreen> browser = new WeakReference<>(null);

	private CrackedAutoUpdate() {
	}

	/** The browser screen is the one that can repaint rows immediately. */
	static void attach(ServerBrowserScreen screen) {
		browser = new WeakReference<>(screen);
	}

	/** The client reached the world; inspect the live connection. */
	public static void onJoined(ClientPacketListener handler) {
		Connection connection = handler.getConnection();
		Boolean encrypted = encrypted(connection);
		if (encrypted == null) {
			return;
		}
		String address = serverAddress(connection, handler.getServerData());
		if (address == null || address.isBlank()) {
			return;
		}
		McdbBrowserClient.LOGGER.info("mcdb cracked join: {} encrypted={}", address, encrypted);
		apply(address, encrypted ? "No" : "Yes");
	}

	/**
	 * A login can prove online mode even when the server then rejects us
	 * (for example a whitelist kick). Encryption is installed as soon as the
	 * server sends its Encryption Request.
	 */
	public static void onLoginDisconnect(ClientHandshakePacketListenerImpl handler) {
		Connection connection = field(handler, "connection", Connection.class);
		if (connection == null) {
			return;
		}
		Boolean encrypted = encrypted(connection);
		if (!Boolean.TRUE.equals(encrypted)) {
			return;
		}
		ServerData data = field(handler, "serverData", ServerData.class);
		String address = serverAddress(connection, data);
		if (address == null || address.isBlank()) {
			return;
		}
		McdbBrowserClient.LOGGER.info("mcdb cracked login: {} encrypted=true", address);
		apply(address, "No");
	}

	private static @Nullable String serverAddress(Connection connection, @Nullable ServerData data) {
		try {
			SocketAddress remote = connection.getRemoteAddress();
			if (remote instanceof InetSocketAddress inet && inet.getAddress() != null) {
				return inet.getAddress().getHostAddress() + ":" + inet.getPort();
			}
		} catch (Exception ignored) {
		}
		return data == null || data.ip.isBlank() ? null : data.ip;
	}

	/** True when the connection pipeline has encryption handlers installed. */
	private static @Nullable Boolean encrypted(Connection connection) {
		try {
			Field channelField = Connection.class.getDeclaredField("channel");
			channelField.setAccessible(true);
			Object value = channelField.get(connection);
			if (value instanceof Channel channel) {
				return channel.pipeline().get("decrypt") != null
					|| channel.pipeline().get("encrypt") != null;
			}
		} catch (Exception e) {
			McdbBrowserClient.LOGGER.debug("Could not inspect connection encryption", e);
		}
		return null;
	}

	private static <T> @Nullable T field(Object target, String name, Class<T> type) {
		Class<?> current = target.getClass();
		while (current != null) {
			try {
				Field field = current.getDeclaredField(name);
				field.setAccessible(true);
				Object value = field.get(target);
				return type.isInstance(value) ? type.cast(value) : null;
			} catch (NoSuchFieldException e) {
				current = current.getSuperclass();
			} catch (Exception e) {
				return null;
			}
		}
		return null;
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
}
