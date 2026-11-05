package com.mcdbbrowser;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.util.Mth;

public record McdbConfig(ButtonCorner buttonCorner, int buttonOffsetX, int buttonOffsetY,
                         String scannerDir, String pythonCommand) {
	public static final int MAX_OFFSET = 300;
	public static final McdbConfig DEFAULT = new McdbConfig(ButtonCorner.TOP_RIGHT, 5, 6, "", defaultPython());

	private static final Path FILE = FabricLoader.getInstance().getConfigDir().resolve("mcdbbrowser.json");
	private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

	private static McdbConfig current = DEFAULT;

	public McdbConfig {
		buttonCorner = buttonCorner == null ? DEFAULT.buttonCorner : buttonCorner;
		buttonOffsetX = Mth.clamp(buttonOffsetX, 0, MAX_OFFSET);
		buttonOffsetY = Mth.clamp(buttonOffsetY, 0, MAX_OFFSET);
		scannerDir = scannerDir == null ? "" : scannerDir.strip();
		pythonCommand = pythonCommand == null || pythonCommand.isBlank()
			? defaultPython() : pythonCommand.strip();
	}

	private static String defaultPython() {
		return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win")
			? "python" : "python3";
	}

	public static McdbConfig get() {
		return current;
	}

	static void load() {
		if (!Files.isRegularFile(FILE)) {
			return;
		}

		try (Reader reader = Files.newBufferedReader(FILE)) {
			McdbConfig loaded = GSON.fromJson(reader, McdbConfig.class);
			if (loaded != null) {
				current = loaded;
			}
		} catch (IOException | JsonParseException e) {
			McdbBrowserClient.LOGGER.warn("Could not read {}, using defaults", FILE, e);
		}
	}

	public static void set(McdbConfig config) {
		current = config;
		try (Writer writer = Files.newBufferedWriter(FILE)) {
			GSON.toJson(config, writer);
		} catch (IOException e) {
			McdbBrowserClient.LOGGER.warn("Could not save {}", FILE, e);
		}
	}

	public McdbConfig withButtonCorner(ButtonCorner corner) {
		return new McdbConfig(corner, this.buttonOffsetX, this.buttonOffsetY,
			this.scannerDir, this.pythonCommand);
	}

	public McdbConfig withButtonOffsetX(int offsetX) {
		return new McdbConfig(this.buttonCorner, offsetX, this.buttonOffsetY,
			this.scannerDir, this.pythonCommand);
	}

	public McdbConfig withButtonOffsetY(int offsetY) {
		return new McdbConfig(this.buttonCorner, this.buttonOffsetX, offsetY,
			this.scannerDir, this.pythonCommand);
	}

	public McdbConfig withScannerDir(String scannerDir) {
		return new McdbConfig(this.buttonCorner, this.buttonOffsetX,
			this.buttonOffsetY, scannerDir, this.pythonCommand);
	}

	public McdbConfig withPythonCommand(String pythonCommand) {
		return new McdbConfig(this.buttonCorner, this.buttonOffsetX,
			this.buttonOffsetY, this.scannerDir, pythonCommand);
	}

	public int buttonX(int screenWidth, int buttonWidth) {
		return this.buttonCorner.right ? screenWidth - buttonWidth - this.buttonOffsetX : this.buttonOffsetX;
	}

	public int buttonY(int screenHeight, int buttonHeight) {
		return this.buttonCorner.bottom ? screenHeight - buttonHeight - this.buttonOffsetY : this.buttonOffsetY;
	}

	public enum ButtonCorner implements ServerDatabase.Labeled {
		TOP_RIGHT("Top right", true, false),
		TOP_LEFT("Top left", false, false),
		BOTTOM_RIGHT("Bottom right", true, true),
		BOTTOM_LEFT("Bottom left", false, true);

		private final String label;
		private final boolean right;
		private final boolean bottom;

		ButtonCorner(String label, boolean right, boolean bottom) {
			this.label = label;
			this.right = right;
			this.bottom = bottom;
		}

		@Override
		public String label() {
			return this.label;
		}
	}
}
