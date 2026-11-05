package com.mcdbbrowser;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
import net.fabricmc.loader.api.FabricLoader;
import org.jspecify.annotations.Nullable;
import org.sqlite.SQLiteConfig;
import org.sqlite.SQLiteDataSource;
import org.sqlite.SQLiteOpenMode;

public final class ServerDatabase {
	public static final String DB_URL = "https://mcdb.uniq.gay/servers.db";
	private static final Path CACHE_DIR = FabricLoader.getInstance().getGameDir().resolve("mcdbbrowser");
	private static final Path DB_FILE = CACHE_DIR.resolve("servers.db");
	private static final long MAX_DOWNLOAD_BYTES = 512L * 1024 * 1024;
	private static final String COLUMNS = String.join(", ",
		"substr(ip_port, 1, 300) AS ip_port",
		"substr(motd, 1, 1024) AS motd",
		"players_online",
		"max_players",
		"substr(version, 1, 256) AS version",
		"protocol",
		"cracked",
		"substr(whitelist, 1, 1024) AS whitelist",
		"(SELECT MIN(seen_at) FROM server_history h WHERE h.ip_port = s.ip_port) AS first_seen",
		"(SELECT MAX(seen_at) FROM server_history h WHERE h.ip_port = s.ip_port) AS last_seen",
		"times_seen",
		"substr(players_now, 1, 16384) AS players_now"
	);
	private static final String SERVERS_FROM = " FROM server_state s";
	/** Every object the file may contain, compared against sqlite_schema exactly. See {@link #validateSchema}. */
	private static final Set<SchemaObject> EXPECTED_SCHEMA = Set.of(
		new SchemaObject("table", "server_state", "server_state", "CREATE TABLE \"server_state\" (ip_port TEXT PRIMARY KEY, host TEXT DEFAULT '', port INTEGER DEFAULT 25565, motd TEXT DEFAULT '', players_online INTEGER DEFAULT 0, max_players INTEGER DEFAULT 0, version TEXT DEFAULT '', protocol INTEGER, cracked INTEGER DEFAULT 0, whitelist TEXT DEFAULT '', times_seen INTEGER DEFAULT 1, last_source TEXT DEFAULT '', seq INTEGER DEFAULT 0, players_now TEXT, players_ever TEXT)"),
		new SchemaObject("index", "sqlite_autoindex_server_state_1", "server_state", null),
		new SchemaObject("table", "server_history", "server_history", "CREATE TABLE server_history ( ip_port TEXT NOT NULL, seen_at REAL NOT NULL, players_online INTEGER, max_players INTEGER, synced INTEGER DEFAULT 0, players TEXT, PRIMARY KEY (ip_port, seen_at))"),
		new SchemaObject("index", "sqlite_autoindex_server_history_1", "server_history", null),
		new SchemaObject("table", "db_meta", "db_meta", "CREATE TABLE db_meta ( key TEXT PRIMARY KEY, value TEXT)"),
		new SchemaObject("index", "sqlite_autoindex_db_meta_1", "db_meta", null),
		new SchemaObject("index", "idx_server_state_seq", "server_state", "CREATE INDEX idx_server_state_seq ON server_state(seq ASC)"),
		new SchemaObject("index", "idx_server_state_version", "server_state", "CREATE INDEX idx_server_state_version ON server_state(version)"),
		new SchemaObject("index", "idx_server_history_unsynced", "server_history", "CREATE INDEX idx_server_history_unsynced ON server_history(seen_at ASC) WHERE synced=0"),
		new SchemaObject("index", "idx_server_history_players_time", "server_history", "CREATE INDEX idx_server_history_players_time ON server_history(seen_at DESC) WHERE players IS NOT NULL"),
		new SchemaObject("view", "servers", "servers", "CREATE VIEW servers AS SELECT s.*, (SELECT MIN(seen_at) FROM server_history h  WHERE h.ip_port=s.ip_port) AS first_seen, (SELECT MAX(seen_at) FROM server_history h  WHERE h.ip_port=s.ip_port) AS last_seen FROM server_state s")
	);
	private static final String SEARCH_CONDITION = "(ip_port LIKE ?%1$d ESCAPE '\\' OR motd LIKE ?%1$d ESCAPE '\\' OR version LIKE ?%1$d ESCAPE '\\' OR players_ever LIKE ?%1$d ESCAPE '\\')";

	private static final ExecutorService WORKER = Executors.newSingleThreadExecutor(runnable -> {
		Thread thread = new Thread(runnable, "MCDB Worker");
		thread.setDaemon(true);
		return thread;
	});
	private static final HttpClient HTTP = HttpClient.newBuilder()
		.followRedirects(HttpClient.Redirect.NORMAL)
		.connectTimeout(Duration.ofSeconds(15))
		.build();
	private static final AtomicLong latestQueryId = new AtomicLong();

	private static @Nullable Connection connection;
	private static volatile long downloadedAtMillis;

	private ServerDatabase() {
	}

	public static boolean isLoaded() {
		return connection != null;
	}

	public static long downloadedAtMillis() {
		return downloadedAtMillis;
	}

	static void deleteLeftoverFiles() {
		if (!Files.isDirectory(CACHE_DIR)) {
			return;
		}

		try (DirectoryStream<Path> leftovers = Files.newDirectoryStream(CACHE_DIR, "{*.part,*-wal,*-shm,*-journal}")) {
			for (Path leftover : leftovers) {
				Files.deleteIfExists(leftover);
			}
		} catch (IOException e) {
			McdbBrowserClient.LOGGER.warn("Could not delete leftover files in {}", CACHE_DIR, e);
		}
	}

	public static CompletableFuture<Void> load(boolean forceDownload, DownloadProgress progress) {
		return CompletableFuture.runAsync(() -> {
			if (connection != null && !forceDownload) {
				return;
			}

			try {
				if (forceDownload || !tryOpenCached()) {
					download(progress);
					open();
				}
			} catch (IOException | SQLException e) {
				throw new CompletionException(e);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new CompletionException(e);
			}
		}, WORKER);
	}

	private static boolean tryOpenCached() {
		if (!Files.isRegularFile(DB_FILE)) {
			return false;
		}

		try {
			open();
			return true;
		} catch (SQLException e) {
			McdbBrowserClient.LOGGER.warn("Cached server list is unreadable, downloading it again", e);
			return false;
		}
	}

	private static void download(DownloadProgress progress) throws IOException, InterruptedException {
		HttpRequest request = HttpRequest.newBuilder(URI.create(DB_URL)).header("User-Agent", "mcdb-browser-fabric/1.0").build();
		HttpResponse<InputStream> response = HTTP.send(request, HttpResponse.BodyHandlers.ofInputStream());
		if (response.statusCode() != 200) {
			response.body().close();
			throw new IOException("HTTP " + response.statusCode() + " from " + DB_URL);
		}

		long totalBytes = response.headers().firstValueAsLong("Content-Length").orElse(-1L);
		if (totalBytes > MAX_DOWNLOAD_BYTES) {
			response.body().close();
			throw new IOException("Server list is too large (" + totalBytes + " bytes)");
		}
		Files.createDirectories(CACHE_DIR);
		Path partial = Files.createTempFile(CACHE_DIR, "servers-", ".part");
		try (InputStream in = response.body(); OutputStream out = Files.newOutputStream(partial)) {
			byte[] buffer = new byte[64 * 1024];
			long downloadedBytes = 0;
			int read;
			while ((read = in.read(buffer)) != -1) {
				out.write(buffer, 0, read);
				downloadedBytes += read;
				if (downloadedBytes > MAX_DOWNLOAD_BYTES) {
					throw new IOException("Server list is larger than " + MAX_DOWNLOAD_BYTES + " bytes");
				}
				progress.update(downloadedBytes, totalBytes);
			}
		} catch (IOException e) {
			Files.deleteIfExists(partial);
			throw e;
		}

		close();
		Files.move(partial, DB_FILE, StandardCopyOption.REPLACE_EXISTING);
	}

	private static void open() throws SQLException {
		SQLiteConfig config = new SQLiteConfig();
		config.setReadOnly(true);
		config.enableLoadExtension(false);
		config.setOpenMode(SQLiteOpenMode.OPEN_URI);
		SQLiteDataSource dataSource = new SQLiteDataSource(config);
		// immutable=1 stops SQLite from reading or creating -wal/-shm side files, so only the downloaded bytes are ever used
		dataSource.setUrl("jdbc:sqlite:" + DB_FILE.toAbsolutePath().toUri() + "?immutable=1");

		Connection opened = dataSource.getConnection();
		try {
			validateSchema(opened);
		} catch (SQLException e) {
			opened.close();
			throw e;
		}

		connection = opened;
		try {
			downloadedAtMillis = Files.getLastModifiedTime(DB_FILE).toMillis();
		} catch (IOException e) {
			downloadedAtMillis = 0;
		}
	}

	/**
	 * The file comes from the network, so its schema is untrusted. SQLite builds each object from the sql column of
	 * sqlite_schema and ignores the type and name columns, so a crafted row labelled as a view could really define a
	 * trigger, a virtual table or a replacement for a table we read. Each row's full text is therefore compared against
	 * {@link #EXPECTED_SCHEMA}, and anything unexpected, duplicated or missing rejects the file. The servers view is
	 * only tolerated: queries read the tables directly and never reference it. trusted_schema=OFF additionally blocks
	 * side-effecting functions in any schema SQL.
	 */
	private static void validateSchema(Connection db) throws SQLException {
		try (Statement statement = db.createStatement()) {
			statement.execute("PRAGMA trusted_schema = OFF");

			Set<SchemaObject> missing = new HashSet<>(EXPECTED_SCHEMA);
			try (ResultSet rs = statement.executeQuery("SELECT type, name, tbl_name, sql FROM sqlite_schema")) {
				while (rs.next()) {
					SchemaObject object = new SchemaObject(rs.getString("type"), rs.getString("name"), rs.getString("tbl_name"), rs.getString("sql"));
					if (!missing.remove(object)) {
						throw new SQLException("Server list has an unexpected " + object.type() + " (" + object.name() + ")");
					}
				}
			}
			if (!missing.isEmpty()) {
				throw new SQLException("Server list is missing " + missing.iterator().next().name());
			}
		}
	}

	private static void close() {
		if (connection == null) {
			return;
		}

		try {
			connection.close();
		} catch (SQLException e) {
			McdbBrowserClient.LOGGER.warn("Failed to close server list database", e);
		}
		connection = null;
		downloadedAtMillis = 0;
	}

	/** Completes with null if a newer query was submitted before this one started. */
	public static CompletableFuture<@Nullable QueryResult> query(Query query) {
		long id = latestQueryId.incrementAndGet();
		return CompletableFuture.supplyAsync(() -> {
			if (id != latestQueryId.get()) {
				return null;
			}

			try {
				return runQuery(query);
			} catch (SQLException e) {
				throw new CompletionException(e);
			}
		}, WORKER);
	}

	/** Completes with null if the address isn't in the database. */
	public static CompletableFuture<@Nullable List<String>> historicalPlayers(String hostAndPort) {
		return CompletableFuture.supplyAsync(() -> {
			if (connection == null) {
				throw new IllegalStateException("Server list not loaded");
			}

			try (PreparedStatement statement = connection.prepareStatement("SELECT substr(players_ever, 1, 65536) FROM server_state WHERE ip_port = ?")) {
				statement.setString(1, hostAndPort);
				try (ResultSet rs = statement.executeQuery()) {
					return rs.next() ? ServerRecord.parsePlayerNames(rs.getString(1)) : null;
				}
			} catch (SQLException e) {
				throw new CompletionException(e);
			}
		}, WORKER);
	}

	private static QueryResult runQuery(Query query) throws SQLException {
		if (connection == null) {
			throw new IllegalStateException("Server list not loaded");
		}

		List<String> searchPatterns = query.searchTerms().stream().map(ServerDatabase::containsPattern).toList();
		StringJoiner where = new StringJoiner(" AND ", " WHERE ", "").setEmptyValue("");
		for (int i = 1; i <= searchPatterns.size(); i++) {
			where.add(SEARCH_CONDITION.formatted(i));
		}
		Stream.of(query.players(), query.auth(), query.whitelist())
			.map(Filter::condition)
			.filter(Objects::nonNull)
			.forEach(where::add);

		String direction = query.descending() ? " DESC" : " ASC";
		String sql = "SELECT " + COLUMNS + SERVERS_FROM + where + " ORDER BY " + query.sort().column + direction + ", last_seen DESC";
		List<ServerRecord> rows = new ArrayList<>();
		try (PreparedStatement statement = connection.prepareStatement(sql)) {
			bind(statement, searchPatterns);
			try (ResultSet rs = statement.executeQuery()) {
				while (rs.next()) {
					rows.add(ServerRecord.fromRow(rs));
				}
			}
		}

		return new QueryResult(rows);
	}

	private static String containsPattern(String term) {
		String escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
		return "%" + escaped + "%";
	}

	private static void bind(PreparedStatement statement, List<String> values) throws SQLException {
		for (int i = 0; i < values.size(); i++) {
			statement.setString(i + 1, values.get(i));
		}
	}

	@FunctionalInterface
	public interface DownloadProgress {
		void update(long downloadedBytes, long totalBytes);
	}

	public interface Labeled {
		String label();
	}

	public interface Filter extends Labeled {
		@Nullable String condition();
	}

	public enum Sort implements Labeled {
		LAST_SEEN("Last seen", "last_seen"),
		FIRST_SEEN("First seen", "first_seen"),
		PLAYERS("Players", "players_online"),
		MAX_PLAYERS("Max players", "max_players"),
		TIMES_SEEN("Times seen", "times_seen"),
		VERSION("Version", "protocol"),
		ADDRESS("Address", "ip_port");

		private final String label;
		private final String column;

		Sort(String label, String column) {
			this.label = label;
			this.column = column;
		}

		@Override
		public String label() {
			return this.label;
		}
	}

	public enum PlayersFilter implements Filter {
		ANY("Any", null),
		ONLINE("Has players", "players_online > 0"),
		EMPTY("Empty", "players_online = 0");

		private final String label;
		private final @Nullable String condition;

		PlayersFilter(String label, @Nullable String condition) {
			this.label = label;
			this.condition = condition;
		}

		@Override
		public String label() {
			return this.label;
		}

		@Override
		public @Nullable String condition() {
			return this.condition;
		}
	}

	public enum AuthFilter implements Filter {
		ANY("Any", null),
		PREMIUM("Online mode", "cracked = 0"),
		CRACKED("Cracked", "cracked = 1");

		private final String label;
		private final @Nullable String condition;

		AuthFilter(String label, @Nullable String condition) {
			this.label = label;
			this.condition = condition;
		}

		@Override
		public String label() {
			return this.label;
		}

		@Override
		public @Nullable String condition() {
			return this.condition;
		}
	}

	public enum WhitelistFilter implements Filter {
		ANY("Any", null),
		OPEN("Open", "whitelist LIKE 'Not Whitelisted%'"),
		WHITELISTED("Whitelisted", "whitelist LIKE 'Whitelisted%'"),
		UNKNOWN("Unknown", "whitelist NOT LIKE 'Whitelisted%' AND whitelist NOT LIKE 'Not Whitelisted%'");

		private final String label;
		private final @Nullable String condition;

		WhitelistFilter(String label, @Nullable String condition) {
			this.label = label;
			this.condition = condition;
		}

		@Override
		public String label() {
			return this.label;
		}

		@Override
		public @Nullable String condition() {
			return this.condition;
		}
	}

	public record Query(String search, Sort sort, boolean descending, PlayersFilter players, AuthFilter auth, WhitelistFilter whitelist) {
		public static final Query DEFAULT = new Query("", Sort.PLAYERS, true, PlayersFilter.ANY, AuthFilter.ANY, WhitelistFilter.ANY);

		List<String> searchTerms() {
			String trimmed = this.search.strip();
			return trimmed.isEmpty() ? List.of() : List.of(trimmed.split("\\s+"));
		}

		public Query withSearch(String search) {
			return new Query(search, this.sort, this.descending, this.players, this.auth, this.whitelist);
		}

		public Query withSort(Sort sort) {
			return new Query(this.search, sort, this.descending, this.players, this.auth, this.whitelist);
		}

		public Query withDescending(boolean descending) {
			return new Query(this.search, this.sort, descending, this.players, this.auth, this.whitelist);
		}

		public Query withPlayers(PlayersFilter players) {
			return new Query(this.search, this.sort, this.descending, players, this.auth, this.whitelist);
		}

		public Query withAuth(AuthFilter auth) {
			return new Query(this.search, this.sort, this.descending, this.players, auth, this.whitelist);
		}

		public Query withWhitelist(WhitelistFilter whitelist) {
			return new Query(this.search, this.sort, this.descending, this.players, this.auth, whitelist);
		}
	}

	public record QueryResult(List<ServerRecord> rows) {
	}

	private record SchemaObject(String type, String name, String table, @Nullable String sql) {
	}
}
