package com.mcdbbrowser;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonIOException;
import com.google.gson.JsonParseException;
import net.fabricmc.loader.api.FabricLoader;

/** The servers most recently joined, newest first, with one entry per address. Public because a mixin calls it. */
public final class ConnectionHistory {
	private static final int MAX_ENTRIES = 15;
	private static final Path FILE = FabricLoader.getInstance().getConfigDir().resolve("mcdbbrowser-history.json");
	private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

	private static List<Entry> entries = List.of();

	private ConnectionHistory() {
	}

	static List<Entry> entries() {
		return entries;
	}

	static void load() {
		if (!Files.isRegularFile(FILE)) {
			return;
		}

		try (Reader reader = Files.newBufferedReader(FILE)) {
			Entry[] loaded = GSON.fromJson(reader, Entry[].class);
			if (loaded != null) {
				entries = Arrays.stream(loaded)
					.filter(Objects::nonNull)
					.filter(entry -> entry.name != null && entry.address != null && !entry.address.isBlank())
					.limit(MAX_ENTRIES)
					.toList();
			}
		} catch (IOException | JsonParseException e) {
			McdbBrowserClient.LOGGER.warn("Could not read {}, starting with an empty history", FILE, e);
		}
	}

	public static void add(String name, String address) {
		List<Entry> updated = new ArrayList<>(MAX_ENTRIES + 1);
		updated.add(new Entry(name, address, System.currentTimeMillis()));
		entries.stream().filter(entry -> !entry.address.equalsIgnoreCase(address)).limit(MAX_ENTRIES - 1).forEach(updated::add);
		entries = List.copyOf(updated);

		try (Writer writer = Files.newBufferedWriter(FILE)) {
			GSON.toJson(entries, writer);
		} catch (IOException | JsonIOException e) {
			McdbBrowserClient.LOGGER.warn("Could not save {}", FILE, e);
		}
	}

	record Entry(String name, String address, long connectedAtMillis) {
	}
}
