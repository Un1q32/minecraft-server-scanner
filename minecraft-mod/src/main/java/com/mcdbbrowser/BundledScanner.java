package com.mcdbbrowser;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.List;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import net.fabricmc.loader.api.FabricLoader;

/**
 * The headless scanner sources are inside the mod jar. Extract them next to
 * the downloaded server list so mcscan.py can run without a separate checkout.
 *
 * The extracted directory also holds the scanner's own servers.db and
 * netdb.json; the browser's downloaded servers.db is a sibling, never shared.
 */
final class BundledScanner {
	private static final List<String> FILES = List.of(
		"scanner.py", "mcscan.py", "db_format.py");
	private static final Path CACHE = FabricLoader.getInstance().getGameDir()
		.resolve("mcdbbrowser");
	private static final Path DIRECTORY = CACHE.resolve("scanner");
	private static final Path CONFIG = DIRECTORY.resolve("netdb.json");
	private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

	private BundledScanner() {
	}

	static synchronized Path ensureExtracted() throws IOException {
		Files.createDirectories(DIRECTORY);
		for (String name : FILES) {
			byte[] data;
			try (InputStream in = BundledScanner.class.getResourceAsStream("/python/" + name)) {
				if (in == null) {
					throw new IOException("bundled " + name + " is missing from the mod jar");
				}
				data = in.readAllBytes();
			}
			Path target = DIRECTORY.resolve(name);
			if (!Files.isRegularFile(target) || !Arrays.equals(Files.readAllBytes(target), data)) {
				Path tmp = Files.createTempFile(DIRECTORY, name + ".", ".tmp");
				Files.write(tmp, data);
				Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
			}
		}
		return DIRECTORY;
	}

	static Path directory() {
		return DIRECTORY;
	}

	static Path configFile() {
		return CONFIG;
	}

	static Credentials loadCredentials() {
		if (!Files.isRegularFile(CONFIG)) {
			return new Credentials("", "");
		}
		try {
			JsonObject json = GSON.fromJson(Files.readString(CONFIG), JsonObject.class);
			if (json == null) {
				return new Credentials("", "");
			}
			return new Credentials(string(json, "url"), string(json, "token"));
		} catch (IOException | JsonParseException e) {
			McdbBrowserClient.LOGGER.warn("Could not read {}", CONFIG, e);
			return new Credentials("", "");
		}
	}

	static void saveCredentials(String url, String token) throws IOException {
		JsonObject json = new JsonObject();
		if (Files.isRegularFile(CONFIG)) {
			try {
				JsonObject existing = GSON.fromJson(Files.readString(CONFIG), JsonObject.class);
				if (existing != null) {
					json = existing;
				}
			} catch (JsonParseException e) {
				// Replace a malformed file rather than refusing to save.
			}
		}
		String normalized = url == null ? "" : url.strip();
		if (!normalized.isEmpty() && !normalized.contains("://")) {
			normalized = "https://" + normalized;
		}
		normalized = normalized.replaceAll("/+$", "");
		String previous = string(json, "url");
		json.addProperty("url", normalized);
		json.addProperty("token", token == null ? "" : token.strip());
		if (!normalized.equals(previous)) {
			// A different server has different row/sequence cursors.
			for (String key : List.of("last_sync", "last_seq", "last_notes_seq",
					"last_history_seq", "last_player_seq")) {
				json.addProperty(key, 0);
			}
		}
		Files.createDirectories(DIRECTORY);
		Path tmp = Files.createTempFile(DIRECTORY, "netdb.", ".tmp");
		Files.writeString(tmp, GSON.toJson(json));
		Files.move(tmp, CONFIG, StandardCopyOption.REPLACE_EXISTING);
	}

	private static String string(JsonObject json, String name) {
		try {
			return json.has(name) && !json.get(name).isJsonNull()
				? json.get(name).getAsString().strip() : "";
		} catch (RuntimeException e) {
			return "";
		}
	}

	record Credentials(String url, String token) {
		boolean configured() {
			return !this.url.isEmpty() && !this.token.isEmpty();
		}
	}
}
