package com.mcdbbrowser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.jspecify.annotations.Nullable;
import org.sqlite.SQLiteConfig;
import org.sqlite.SQLiteDataSource;
import org.sqlite.SQLiteOpenMode;

/**
 * Reads and writes the scanner's local notes.db.
 *
 * The shared notes format is append-only: a note's text never changes, and a
 * delete is a tombstone (text becomes NULL, needs_sync becomes 1). "Editing" an
 * existing note therefore tombstones it and creates a replacement in one
 * transaction, exactly like doing it by hand in the scanner UI.
 */
final class NotesDatabase {
	static final int MAX_NOTE_CHARS = 4000;

	private static final ExecutorService WORKER = Executors.newSingleThreadExecutor(runnable -> {
		Thread thread = new Thread(runnable, "MCDB Notes");
		thread.setDaemon(true);
		return thread;
	});

	private NotesDatabase() {
	}

	record Note(String id, String ipPort, String text, double createdAt, double updatedAt) {
	}

	static CompletableFuture<List<Note>> list(String ipPort) {
		return CompletableFuture.supplyAsync(() -> {
			try (Connection connection = open()) {
				List<Note> notes = new ArrayList<>();
				try (PreparedStatement statement = connection.prepareStatement(
						"SELECT id, ip_port, text, created_at, updated_at FROM notes"
							+ " WHERE ip_port = ? AND text IS NOT NULL"
							+ " ORDER BY created_at ASC, id ASC")) {
					statement.setString(1, ipPort);
					try (ResultSet rs = statement.executeQuery()) {
						while (rs.next()) {
							notes.add(read(rs));
						}
					}
				}
				return notes;
			} catch (SQLException e) {
				throw new CompletionException(e);
			}
		}, WORKER);
	}

	static CompletableFuture<Note> add(String ipPort, String text) {
		return CompletableFuture.supplyAsync(() -> {
			String body = normalize(text);
			if (body.isEmpty()) {
				throw new IllegalArgumentException("Note is empty");
			}
			String id = UUID.randomUUID().toString();
			double now = now();
			try (Connection connection = open();
				 PreparedStatement statement = connection.prepareStatement(
					 "INSERT INTO notes (id, ip_port, text, created_at, updated_at, needs_sync)"
						 + " VALUES (?, ?, ?, ?, ?, 1)")) {
				statement.setString(1, id);
				statement.setString(2, ipPort);
				statement.setString(3, body);
				statement.setDouble(4, now);
				statement.setDouble(5, now);
				statement.executeUpdate();
				return new Note(id, ipPort, body, now, now);
			} catch (SQLException e) {
				throw new CompletionException(e);
			}
		}, WORKER);
	}

	/** Tombstone the old note and insert its replacement as a new note. */
	static CompletableFuture<Note> replace(String oldId, String ipPort, String text) {
		return CompletableFuture.supplyAsync(() -> {
			String body = normalize(text);
			if (body.isEmpty()) {
				throw new IllegalArgumentException("Note is empty");
			}
			String id = UUID.randomUUID().toString();
			double now = now();
			try (Connection connection = open()) {
				connection.setAutoCommit(false);
				try {
					try (PreparedStatement delete = connection.prepareStatement(
							"UPDATE notes SET text = NULL, updated_at = ?, needs_sync = 1"
								+ " WHERE id = ? AND ip_port = ? AND text IS NOT NULL")) {
						delete.setDouble(1, now);
						delete.setString(2, oldId);
						delete.setString(3, ipPort);
						delete.executeUpdate();
					}
					try (PreparedStatement insert = connection.prepareStatement(
							"INSERT INTO notes (id, ip_port, text, created_at, updated_at, needs_sync)"
								+ " VALUES (?, ?, ?, ?, ?, 1)")) {
						insert.setString(1, id);
						insert.setString(2, ipPort);
						insert.setString(3, body);
						insert.setDouble(4, now);
						insert.setDouble(5, now);
						insert.executeUpdate();
					}
					connection.commit();
					return new Note(id, ipPort, body, now, now);
				} catch (SQLException e) {
					connection.rollback();
					throw e;
				}
			} catch (SQLException e) {
				throw new CompletionException(e);
			}
		}, WORKER);
	}

	static CompletableFuture<Boolean> delete(String id) {
		return CompletableFuture.supplyAsync(() -> {
			try (Connection connection = open();
				 PreparedStatement statement = connection.prepareStatement(
					 "UPDATE notes SET text = NULL, updated_at = ?, needs_sync = 1"
						 + " WHERE id = ? AND text IS NOT NULL")) {
				statement.setDouble(1, now());
				statement.setString(2, id);
				return statement.executeUpdate() > 0;
			} catch (SQLException e) {
				throw new CompletionException(e);
			}
		}, WORKER);
	}

	private static Connection open() throws SQLException {
		try {
			BundledScanner.ensureExtracted();
		} catch (IOException e) {
			throw new SQLException("Could not create the scanner directory", e);
		}
		Path database = BundledScanner.directory().resolve("notes.db");
		try {
			Files.createDirectories(database.getParent());
		} catch (IOException e) {
			throw new SQLException("Could not create " + database.getParent(), e);
		}

		SQLiteConfig config = new SQLiteConfig();
		config.setOpenMode(SQLiteOpenMode.OPEN_URI);
		SQLiteDataSource source = new SQLiteDataSource(config);
		source.setUrl("jdbc:sqlite:" + database.toAbsolutePath().toUri());
		Connection connection = source.getConnection();
		try (Statement statement = connection.createStatement()) {
			statement.execute("PRAGMA busy_timeout = 10000");
			statement.execute("PRAGMA journal_mode = WAL");
			statement.execute("PRAGMA synchronous = NORMAL");
			statement.execute("PRAGMA secure_delete = ON");
			statement.execute("CREATE TABLE IF NOT EXISTS notes ("
				+ " id TEXT PRIMARY KEY,"
				+ " ip_port TEXT NOT NULL,"
				+ " text TEXT,"
				+ " created_at REAL DEFAULT 0,"
				+ " updated_at REAL DEFAULT 0,"
				+ " needs_sync INTEGER DEFAULT 1)");
			ensureNeedsSync(statement);
			statement.execute("CREATE INDEX IF NOT EXISTS idx_notes_ip ON notes(ip_port)");
			statement.execute("CREATE INDEX IF NOT EXISTS idx_notes_created ON notes(created_at ASC)");
		} catch (SQLException e) {
			connection.close();
			throw e;
		}
		return connection;
	}

	private static void ensureNeedsSync(Statement statement) throws SQLException {
		boolean present = false;
		try (ResultSet columns = statement.executeQuery("PRAGMA table_info(notes)")) {
			while (columns.next()) {
				if ("needs_sync".equalsIgnoreCase(columns.getString("name"))) {
					present = true;
					break;
				}
			}
		}
		if (!present) {
			statement.execute("ALTER TABLE notes ADD COLUMN needs_sync INTEGER DEFAULT 0");
		}
	}

	private static Note read(ResultSet rs) throws SQLException {
		return new Note(
			rs.getString("id"),
			rs.getString("ip_port"),
			rs.getString("text"),
			rs.getDouble("created_at"),
			rs.getDouble("updated_at"));
	}

	private static String normalize(@Nullable String text) {
		String body = text == null ? "" : text.strip();
		return body.length() <= MAX_NOTE_CHARS ? body : body.substring(0, MAX_NOTE_CHARS);
	}

	private static double now() {
		return System.currentTimeMillis() / 1000.0;
	}
}
