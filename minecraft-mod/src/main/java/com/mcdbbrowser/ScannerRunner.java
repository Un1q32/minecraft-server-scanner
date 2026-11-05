package com.mcdbbrowser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import net.fabricmc.loader.api.FabricLoader;
import org.jspecify.annotations.Nullable;

/**
 * Runs the local mcscan.py commands used by the Rescan, Recheck Whitelist and
 * Sync DB buttons. The scanner keeps its own servers.db and netdb.json, so the
 * mod only needs the path to the checkout (or a nearby auto-detected one).
 */
final class ScannerRunner {
	private static final int SCAN_TIMEOUT_SECONDS = 180;
	private static final int WHITELIST_TIMEOUT_SECONDS = 300;
	private static final int SYNC_TIMEOUT_SECONDS = 300;
	private static final int MAX_STATUS_CHARS = 120;

	private static final ExecutorService WORKER = Executors.newSingleThreadExecutor(runnable -> {
		Thread thread = new Thread(runnable, "MCDB Scanner");
		thread.setDaemon(true);
		return thread;
	});

	private ScannerRunner() {
	}

	record Result(boolean ok, String message) {
	}

	static CompletableFuture<Result> rescan(String address, Consumer<String> progress) {
		return CompletableFuture.supplyAsync(() -> {
			Result scan = runStep(List.of("--rescan", address), SCAN_TIMEOUT_SECONDS, progress);
			if (!scan.ok()) {
				return scan;
			}
			Result sync = runStep(List.of("--sync"), SYNC_TIMEOUT_SECONDS, progress);
			return sync.ok()
				? new Result(true, "Rescanned " + address + " and synced")
				: new Result(false, "Rescan finished, but sync failed: " + sync.message());
		}, WORKER);
	}

	static CompletableFuture<Result> recheckWhitelist(String address, Consumer<String> progress) {
		return CompletableFuture.supplyAsync(() -> {
			Result check = runStep(List.of("--recheck-whitelist", address),
				WHITELIST_TIMEOUT_SECONDS, progress);
			if (!check.ok()) {
				return check;
			}
			Result sync = runStep(List.of("--sync"), SYNC_TIMEOUT_SECONDS, progress);
			return sync.ok()
				? new Result(true, "Whitelist checked for " + address + " and synced")
				: new Result(false, "Whitelist check finished, but sync failed: " + sync.message());
		}, WORKER);
	}

	static CompletableFuture<Result> sync(Consumer<String> progress) {
		return CompletableFuture.supplyAsync(() -> {
			Result sync = runStep(List.of("--sync"), SYNC_TIMEOUT_SECONDS, progress);
			return sync.ok() ? new Result(true, "Shared DB synced") : sync;
		}, WORKER);
	}

	private static Result runStep(List<String> args, int timeoutSeconds, Consumer<String> progress) {
		Path directory = scannerDirectory();
		if (directory == null) {
			return new Result(false, "Set the scanner directory in Settings (the folder containing mcscan.py)");
		}

		List<String> command = new ArrayList<>();
		command.addAll(pythonCommand());
		command.add("mcscan.py");
		command.addAll(args);

		Process process;
		try {
			process = new ProcessBuilder(command)
				.directory(directory.toFile())
				.redirectErrorStream(true)
				.start();
		} catch (IOException e) {
			return new Result(false, "Could not start " + String.join(" ", command) + ": " + e.getMessage());
		}

		CompletableFuture<String> output = CompletableFuture.supplyAsync(
			() -> readOutput(process.getInputStream(), progress));
		try {
			if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
				process.destroyForcibly();
				return new Result(false, "Timed out after " + timeoutSeconds + "s");
			}
			String text = output.get(5, TimeUnit.SECONDS);
			if (process.exitValue() != 0) {
				return new Result(false, lastLine(text, "exit code " + process.exitValue()));
			}
			return new Result(true, lastLine(text, "done"));
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			process.destroyForcibly();
			return new Result(false, "Interrupted");
		} catch (Exception e) {
			process.destroyForcibly();
			Throwable cause = e instanceof CompletionException && e.getCause() != null ? e.getCause() : e;
			return new Result(false, cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage());
		}
	}

	private static String readOutput(InputStream stream, Consumer<String> progress) {
		StringBuilder tail = new StringBuilder();
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
			String line;
			while ((line = reader.readLine()) != null) {
				line = line.strip();
				if (line.isEmpty()) {
					continue;
				}
				progress.accept(shorten(line));
				tail.append(line).append('\n');
				if (tail.length() > 4096) {
					tail.delete(0, tail.length() - 4096);
				}
			}
		} catch (IOException e) {
			// The process is gone; the exit code below is the useful signal.
		}
		return tail.toString();
	}

	private static String lastLine(String text, String fallback) {
		String trimmed = text == null ? "" : text.strip();
		if (trimmed.isEmpty()) {
			return fallback;
		}
		int newline = trimmed.lastIndexOf('\n');
		return shorten(newline >= 0 ? trimmed.substring(newline + 1) : trimmed);
	}

	private static String shorten(String text) {
		return text.length() <= MAX_STATUS_CHARS ? text : text.substring(0, MAX_STATUS_CHARS) + "…";
	}

	private static List<String> pythonCommand() {
		String configured = McdbConfig.get().pythonCommand();
		if (configured == null || configured.isBlank()) {
			configured = System.getProperty("os.name", "").toLowerCase().contains("win")
				? "python" : "python3";
		}
		return List.of(configured.strip().split("\\s+"));
	}

	private static @Nullable Path scannerDirectory() {
		String configured = McdbConfig.get().scannerDir();
		if (configured != null && !configured.isBlank()) {
			Path path = Path.of(configured).toAbsolutePath().normalize();
			return Files.isRegularFile(path.resolve("mcscan.py")) ? path : null;
		}

		List<Path> starts = new ArrayList<>();
		starts.add(Path.of("").toAbsolutePath());
		try {
			starts.add(FabricLoader.getInstance().getGameDir().toAbsolutePath());
		} catch (RuntimeException e) {
			// Fabric is always present, but never let a lookup break the UI.
		}
		for (Path start : starts) {
			Path current = start;
			for (int depth = 0; current != null && depth < 6; depth++) {
				if (Files.isRegularFile(current.resolve("mcscan.py"))) {
					return current;
				}
				Path sibling = current.resolveSibling("minecraft-server-scanner");
				if (Files.isRegularFile(sibling.resolve("mcscan.py"))) {
					return sibling;
				}
				current = current.getParent();
			}
		}
		return null;
	}
}
