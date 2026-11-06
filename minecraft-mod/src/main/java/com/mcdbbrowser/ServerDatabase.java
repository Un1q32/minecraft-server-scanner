package com.mcdbbrowser;

import java.io.FilterInputStream;
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
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
import com.github.luben.zstd.ZstdInputStream;
import net.fabricmc.loader.api.FabricLoader;
import org.jspecify.annotations.Nullable;
import org.sqlite.SQLiteConfig;
import org.sqlite.SQLiteDataSource;
import org.sqlite.SQLiteOpenMode;

public final class ServerDatabase {
	public static final String DB_URL = "https://mcdb.uniq.gay/servers.db.zst";
	private static final String PLAIN_DB_URL = "https://mcdb.uniq.gay/servers.db";
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
		"port",
		"substr(last_source, 1, 300) AS last_source",
		"substr(players_now, 1, 16384) AS players_now",
		"substr(players_ever, 1, 65536) AS players_ever"
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
	/** A host with this many identical ports is almost certainly one server behind a port spray. */
	private static final int DEDUP_MIN_PORTS = 5;
	private static final int DEDUP_PORT_PREVIEW = 10;

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

	/**
	 * Downloads the compact zstd snapshot. The live servers.db is written in
	 * place and can be captured mid-write, which surfaced as "corrupt" after
	 * Redownload; the snapshot is produced with VACUUM INTO and an atomic
	 * rename, so it is always a consistent database. A plain download is only
	 * used when the host does not publish a snapshot.
	 */
	private static void download(DownloadProgress progress) throws IOException, InterruptedException {
		IOException failure = null;
		for (int attempt = 0; attempt < 2; attempt++) {
			try {
				downloadSnapshot(URI.create(DB_URL), true, progress);
				return;
			} catch (MissingSnapshotException e) {
				downloadSnapshot(URI.create(PLAIN_DB_URL), false, progress);
				return;
			} catch (IOException e) {
				failure = e;
				if (attempt == 0) {
					try {
						Thread.sleep(750L);
					} catch (InterruptedException interrupted) {
						Thread.currentThread().interrupt();
						throw interrupted;
					}
				}
			}
		}
		throw failure != null ? failure : new IOException("Download failed");
	}

	private static void downloadSnapshot(URI uri, boolean compressed, DownloadProgress progress)
			throws IOException, InterruptedException {
		HttpRequest request = HttpRequest.newBuilder(uri).header("User-Agent", "mcdb-browser-fabric/1.0").build();
		HttpResponse<InputStream> response = HTTP.send(request, HttpResponse.BodyHandlers.ofInputStream());
		if (response.statusCode() != 200) {
			response.body().close();
			if (compressed && response.statusCode() == 404) {
				throw new MissingSnapshotException();
			}
			throw new IOException("HTTP " + response.statusCode() + " from " + uri);
		}

		long totalBytes = response.headers().firstValueAsLong("Content-Length").orElse(-1L);
		if (totalBytes > MAX_DOWNLOAD_BYTES) {
			response.body().close();
			throw new IOException("Server list is too large (" + totalBytes + " bytes)");
		}
		Files.createDirectories(CACHE_DIR);
		Path partial = Files.createTempFile(CACHE_DIR, "servers-", ".part");
		try {
			try (InputStream body = response.body();
				 CountingInputStream network = new CountingInputStream(body);
				 InputStream in = compressed ? new ZstdInputStream(network) : network;
				 OutputStream out = Files.newOutputStream(partial)) {
				byte[] buffer = new byte[64 * 1024];
				long written = 0;
				int read;
				while ((read = in.read(buffer)) != -1) {
					out.write(buffer, 0, read);
					written += read;
					if (written > MAX_DOWNLOAD_BYTES) {
						throw new IOException("Server list is larger than " + MAX_DOWNLOAD_BYTES + " bytes");
					}
					progress.update(network.count(), totalBytes);
				}
			}

			// Never replace a working cache with a torn or truncated download.
			try (Connection check = openReadOnly(partial)) {
				validateSchema(check);
				try (Statement statement = check.createStatement();
					 ResultSet rs = statement.executeQuery("PRAGMA quick_check")) {
					while (rs.next()) {
						String result = rs.getString(1);
						if (!"ok".equalsIgnoreCase(result)) {
							throw new SQLException("Server list integrity check failed: " + result);
						}
					}
				}
			} catch (SQLException e) {
				throw new IOException("Downloaded server list is corrupt: " + describe(e), e);
			}

			close();
			Files.move(partial, DB_FILE, StandardCopyOption.REPLACE_EXISTING);
			partial = null;
		} finally {
			if (partial != null) {
				Files.deleteIfExists(partial);
			}
		}
	}

	private static String describe(SQLException e) {
		return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
	}

	private static void open() throws SQLException {
		Connection opened = openReadOnly(DB_FILE);
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

	private static Connection openReadOnly(Path file) throws SQLException {
		SQLiteConfig config = new SQLiteConfig();
		config.setReadOnly(true);
		config.enableLoadExtension(false);
		config.setOpenMode(SQLiteOpenMode.OPEN_URI);
		SQLiteDataSource dataSource = new SQLiteDataSource(config);
		// immutable=1 stops SQLite from reading or creating -wal/-shm side files, so only the downloaded bytes are ever used
		dataSource.setUrl("jdbc:sqlite:" + file.toAbsolutePath().toUri() + "?immutable=1");
		return dataSource.getConnection();
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
					if (object.type().equals("table") && object.name().equals("server_state")) {
						// Shared DBs initialized from a scanner DB carry the
						// scanner-only needs_sync flag. It does not affect the
						// browser queries, so accept it as an optional column.
						object = new SchemaObject(object.type(), object.name(), object.table(),
							object.sql() == null ? null : object.sql().replaceAll(
								",\\s*needs_sync\\s+INTEGER\\s+DEFAULT\\s+\\d+", ""));
					}
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
	public static CompletableFuture<@Nullable QueryResult> query(Query query, List<SortKey> sortKeys) {
		long id = latestQueryId.incrementAndGet();
		return CompletableFuture.supplyAsync(() -> {
			if (id != latestQueryId.get()) {
				return null;
			}

			try {
				return runQuery(query, sortKeys);
			} catch (SQLException e) {
				throw new CompletionException(e);
			}
		}, WORKER);
	}

	/** Current whitelist label for an address, or null when the DB is not the source of truth. */
	public static CompletableFuture<@Nullable String> whitelistOf(String address) {
		return CompletableFuture.supplyAsync(() -> {
			if (connection == null) {
				return null;
			}
			try (PreparedStatement statement = connection.prepareStatement(
					"SELECT whitelist FROM server_state WHERE ip_port = ?")) {
				statement.setString(1, address);
				try (ResultSet rs = statement.executeQuery()) {
					return rs.next() ? rs.getString(1) : null;
				}
			} catch (SQLException e) {
				throw new CompletionException(e);
			}
		}, WORKER);
	}

	/**
	 * Patch the downloaded browser cache with a whitelist verdict we observed
	 * directly. The cache is replaced by the next full download anyway, so this
	 * only avoids a 250 MB round-trip (and keeps the list correct immediately).
	 */
	public static CompletableFuture<Void> setWhitelist(String address, String label) {
		return CompletableFuture.runAsync(() -> {
			if (!Files.isRegularFile(DB_FILE)) {
				return;
			}
			boolean wasOpen = connection != null;
			if (wasOpen) {
				close();
			}
			try {
				SQLiteConfig config = new SQLiteConfig();
				config.setReadOnly(false);
				config.setOpenMode(SQLiteOpenMode.OPEN_URI);
				SQLiteDataSource source = new SQLiteDataSource(config);
				source.setUrl("jdbc:sqlite:" + DB_FILE.toAbsolutePath().toUri());
				try (Connection database = source.getConnection()) {
					try (Statement pragma = database.createStatement()) {
						pragma.execute("PRAGMA journal_mode=DELETE");
					}
					try (PreparedStatement statement = database.prepareStatement(
							"UPDATE server_state SET whitelist = ? WHERE ip_port = ?")) {
						statement.setString(1, label);
						statement.setString(2, address);
						statement.executeUpdate();
					}
				}
			} catch (SQLException e) {
				McdbBrowserClient.LOGGER.warn("Could not cache the whitelist for {}", address, e);
			} finally {
				if (wasOpen) {
					try {
						open();
					} catch (SQLException e) {
						McdbBrowserClient.LOGGER.warn("Could not reopen the server list after a whitelist update", e);
					}
				}
			}
		}, WORKER);
	}

	public record HistoryPoint(double seenAt, @Nullable Integer playersOnline,
	                           @Nullable Integer maxPlayers) {
	}

	public record PlayerActivity(String name, List<Double> times) {
	}

	public record ServerActivity(List<HistoryPoint> points, List<PlayerActivity> players) {
	}

	/** Sighting and player-activity history for the viewer charts. */
	public static CompletableFuture<ServerActivity> activity(String hostAndPort) {
		return CompletableFuture.supplyAsync(() -> {
			if (connection == null) {
				throw new IllegalStateException("Server list not loaded");
			}
			List<HistoryPoint> points = new ArrayList<>();
			try (PreparedStatement statement = connection.prepareStatement(
					"SELECT seen_at, players_online, max_players FROM ("
						+ " SELECT seen_at, players_online, max_players FROM server_history"
						+ " WHERE ip_port = ? ORDER BY seen_at DESC LIMIT 5000"
						+ ") ORDER BY seen_at ASC")) {
				statement.setString(1, hostAndPort);
				try (ResultSet rs = statement.executeQuery()) {
					while (rs.next()) {
						Integer online = rs.getObject(2) == null ? null : rs.getInt(2);
						Integer max = rs.getObject(3) == null ? null : rs.getInt(3);
						points.add(new HistoryPoint(rs.getDouble(1), online, max));
					}
				}
			} catch (SQLException e) {
				throw new CompletionException(e);
			}

			if (points.isEmpty()) {
				// Older databases still know the first/last sighting.
				try (PreparedStatement statement = connection.prepareStatement(
						"SELECT first_seen, last_seen FROM servers WHERE ip_port = ?")) {
					statement.setString(1, hostAndPort);
					try (ResultSet rs = statement.executeQuery()) {
						if (rs.next()) {
							double first = rs.getDouble(1);
							double last = rs.getDouble(2);
							if (first > 0) {
								points.add(new HistoryPoint(first, null, null));
							}
							if (last > first) {
								points.add(new HistoryPoint(last, null, null));
							}
						}
					}
				} catch (SQLException e) {
					throw new CompletionException(e);
				}
			}

			Map<String, List<Double>> byName = new LinkedHashMap<>();
			int total = 0;
			try (PreparedStatement statement = connection.prepareStatement(
					"SELECT seen_at, players FROM server_history"
						+ " WHERE ip_port = ? AND players IS NOT NULL"
						+ " ORDER BY seen_at DESC LIMIT 20000")) {
				statement.setString(1, hostAndPort);
				try (ResultSet rs = statement.executeQuery()) {
					while (total < 20000 && rs.next()) {
						double seenAt = rs.getDouble(1);
						String blob = rs.getString(2);
						if (blob == null || blob.isEmpty()) {
							continue;
						}
						for (String name : blob.split("\u001f")) {
							if (total >= 20000) {
								break;
							}
							if (!name.isEmpty()) {
								byName.computeIfAbsent(name, key -> new ArrayList<>()).add(seenAt);
								total++;
							}
						}
					}
				}
			} catch (SQLException e) {
				throw new CompletionException(e);
			}

			List<PlayerActivity> players = new ArrayList<>(byName.size());
			for (Map.Entry<String, List<Double>> entry : byName.entrySet()) {
				entry.getValue().sort(Double::compareTo);
				players.add(new PlayerActivity(entry.getKey(), entry.getValue()));
			}
			return new ServerActivity(points, players);
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

	private static QueryResult runQuery(Query query, List<SortKey> sortKeys) throws SQLException {
		if (connection == null) {
			throw new IllegalStateException("Server list not loaded");
		}

		SearchQuery.Result search = SearchQuery.compile(query.search());
		StringJoiner where = new StringJoiner(" AND ", " WHERE ", "").setEmptyValue("");
		if (!search.where().isEmpty()) {
			where.add(search.where().substring("WHERE ".length()));
		}
		Stream.of(query.players(), query.auth(), query.whitelist())
			.map(Filter::condition)
			.filter(Objects::nonNull)
			.forEach(where::add);

		// Wrap the projected columns so search can also reference the derived
		// first_seen/last_seen aliases (WHERE cannot see SELECT aliases).
		String sql = "SELECT * FROM (" + "SELECT " + COLUMNS + SERVERS_FROM + ") q" + where;
		List<ServerRecord> rows = new ArrayList<>();
		try (PreparedStatement statement = connection.prepareStatement(sql)) {
			bind(statement, search.params());
			try (ResultSet rs = statement.executeQuery()) {
				while (rs.next()) {
					rows.add(ServerRecord.fromRow(rs));
				}
			}
		}
		rows = deduplicatePorts(rows);
		// SQLite is already native, but letting it compute derived columns and
		// then sorting Java records keeps sort changes entirely in memory.
		rows.sort(comparator(sortKeys));

		return new QueryResult(rows);
	}

	/**
	 * Collapse a host that answers identically on many ports into one row.
	 *
	 * These are usually a firewall/NAT forwarding a whole port range to one
	 * Minecraft server (the real port is normally 25565). Small groups are
	 * left alone so genuinely separate instances on one machine survive, and
	 * only rows with the same MOTD/version/protocol are grouped.
	 */
	private static List<ServerRecord> deduplicatePorts(List<ServerRecord> rows) {
		Map<String, List<ServerRecord>> byHost = new LinkedHashMap<>();
		for (ServerRecord row : rows) {
			byHost.computeIfAbsent(hostOf(row.address()), key -> new ArrayList<>()).add(row);
		}

		List<ServerRecord> out = new ArrayList<>(rows.size());
		for (List<ServerRecord> hostRows : byHost.values()) {
			if (hostRows.size() < DEDUP_MIN_PORTS) {
				out.addAll(hostRows);
				continue;
			}
			Map<String, List<ServerRecord>> bySignature = new LinkedHashMap<>();
			for (ServerRecord row : hostRows) {
				bySignature.computeIfAbsent(portSignature(row), key -> new ArrayList<>()).add(row);
			}
			for (List<ServerRecord> group : bySignature.values()) {
				if (group.size() < DEDUP_MIN_PORTS) {
					out.addAll(group);
					continue;
				}
				ServerRecord primary = representative(group);
				List<Integer> ports = new ArrayList<>(group.size());
				for (ServerRecord row : group) {
					ports.add(portNumber(row.address()));
				}
				ports.sort(Integer::compareTo);
				List<String> shown = new ArrayList<>(Math.min(DEDUP_PORT_PREVIEW, ports.size()));
				for (int i = 0; i < ports.size() && i < DEDUP_PORT_PREVIEW; i++) {
					shown.add(Integer.toString(ports.get(i)));
				}
				String summary = String.join(", ", shown);
				if (ports.size() > DEDUP_PORT_PREVIEW) {
					summary += " (+" + (ports.size() - DEDUP_PORT_PREVIEW) + " more)";
				}
				out.add(primary.withPortGroup(group.size(), summary));
			}
		}
		return out;
	}

	private static String hostOf(String address) {
		int colon = address.lastIndexOf(':');
		return colon <= 0 ? address : address.substring(0, colon);
	}

	private static int portNumber(String address) {
		int colon = address.lastIndexOf(':');
		if (colon < 0 || colon + 1 >= address.length()) {
			return 0;
		}
		try {
			return Integer.parseInt(address.substring(colon + 1));
		} catch (NumberFormatException e) {
			return 0;
		}
	}

	private static String portSignature(ServerRecord row) {
		return row.motd().strip().toLowerCase(Locale.ROOT) + '\u0000'
			+ row.version().strip().toLowerCase(Locale.ROOT) + '\u0000'
			+ row.protocol();
	}

	private static ServerRecord representative(List<ServerRecord> group) {
		ServerRecord best = group.get(0);
		for (int i = 1; i < group.size(); i++) {
			ServerRecord candidate = group.get(i);
			if (preferred(candidate, best)) {
				best = candidate;
			}
		}
		return best;
	}

	private static boolean preferred(ServerRecord candidate, ServerRecord current) {
		boolean candidateCanonical = portNumber(candidate.address()) == 25565;
		boolean currentCanonical = portNumber(current.address()) == 25565;
		if (candidateCanonical != currentCanonical) {
			return candidateCanonical;
		}
		if (candidate.timesSeen() != current.timesSeen()) {
			return candidate.timesSeen() > current.timesSeen();
		}
		if (candidate.playersOnline() != current.playersOnline()) {
			return candidate.playersOnline() > current.playersOnline();
		}
		return portNumber(candidate.address()) < portNumber(current.address());
	}

	private static void bind(PreparedStatement statement, List<Object> values) throws SQLException {
		for (int i = 0; i < values.size(); i++) {
			Object value = values.get(i);
			if (value instanceof Number number) {
				statement.setLong(i + 1, number.longValue());
			} else {
				statement.setString(i + 1, String.valueOf(value));
			}
		}
	}

	/** One column in the click-order sort stack (last entry is primary). */
	public record SortKey(Sort sort, boolean descending) {
	}

	private record IpKey(boolean v4, int a, int b, int c, int d, int port,
	                     String other) implements Comparable<IpKey> {
		@Override
		public int compareTo(IpKey o) {
			if (this.v4 != o.v4) {
				return this.v4 ? -1 : 1;
			}
			if (this.v4) {
				int result = Integer.compare(this.a, o.a);
				if (result == 0) result = Integer.compare(this.b, o.b);
				if (result == 0) result = Integer.compare(this.c, o.c);
				if (result == 0) result = Integer.compare(this.d, o.d);
				if (result == 0) result = Integer.compare(this.port, o.port);
				return result;
			}
			int result = this.other.compareTo(o.other);
			return result != 0 ? result : Integer.compare(this.port, o.port);
		}
	}

	private static long minuteKey(double epoch) {
		return epoch > 0.0 ? (long) (epoch / 60.0) : 0L;
	}

	private static IpKey ipKey(String value) {
		String host = value == null ? "" : value;
		int port = 0;
		int colons = 0;
		for (int i = 0; i < host.length(); i++) {
			if (host.charAt(i) == ':') colons++;
		}
		if (colons == 1) {
			int index = host.indexOf(':');
			try {
				int parsed = Integer.parseInt(host.substring(index + 1));
				if (parsed >= 0) {
					port = parsed;
					host = host.substring(0, index);
				}
			} catch (RuntimeException e) {
				// Keep the whole value as a hostname.
			}
		}
		String[] parts = host.split("\\.", -1);
		if (parts.length == 4) {
			try {
				int a = Integer.parseInt(parts[0]);
				int b = Integer.parseInt(parts[1]);
				int c = Integer.parseInt(parts[2]);
				int d = Integer.parseInt(parts[3]);
				if (a >= 0 && b >= 0 && c >= 0 && d >= 0) {
					return new IpKey(true, a, b, c, d, port, "");
				}
			} catch (NumberFormatException e) {
				// Hostname.
			}
		}
		return new IpKey(false, 0, 0, 0, 0, port,
			host.toLowerCase(Locale.ROOT));
	}

	private static List<Long> versionKey(String value) {
		List<Long> out = new ArrayList<>();
		for (String token : (value == null ? "" : value.trim()).split("\\.", -1)) {
			if (token.isEmpty()) {
				continue;
			}
			boolean digits = true;
			for (int i = 0; i < token.length(); i++) {
				if (!Character.isDigit(token.charAt(i))) {
					digits = false;
					break;
				}
			}
			if (digits) {
				try {
					out.add(Long.parseLong(token));
				} catch (NumberFormatException e) {
					out.add(0L);
				}
			} else {
				boolean found = false;
				for (String part : token.split("\\D+")) {
					if (part.isEmpty()) continue;
					try {
						out.add(Long.parseLong(part));
					} catch (NumberFormatException e) {
						out.add(0L);
					}
					found = true;
				}
				if (!found) out.add(0L);
			}
		}
		if (out.isEmpty()) out.add(0L);
		return out;
	}

	private static int compareVersionKeys(List<Long> a, List<Long> b) {
		int count = Math.min(a.size(), b.size());
		for (int i = 0; i < count; i++) {
			int result = Long.compare(a.get(i), b.get(i));
			if (result != 0) return result;
		}
		return Integer.compare(a.size(), b.size());
	}

	public static Comparator<ServerRecord> comparator(List<SortKey> keys) {
		Comparator<ServerRecord> comparator = null;
		for (int i = keys.size() - 1; i >= 0; i--) {
			SortKey key = keys.get(i);
			Comparator<ServerRecord> current = key.sort().comparator;
			if (key.descending()) {
				current = current.reversed();
			}
			comparator = comparator == null ? current : comparator.thenComparing(current);
		}
		if (comparator == null) {
			comparator = Comparator.comparingLong(
				(ServerRecord r) -> minuteKey(r.lastSeenEpochSeconds())).reversed();
		}
		return comparator;
	}

	@FunctionalInterface
	public interface DownloadProgress {
		void update(long downloadedBytes, long totalBytes);
	}

	private static final class CountingInputStream extends FilterInputStream {
		private long count;

		CountingInputStream(InputStream in) {
			super(in);
		}

		long count() {
			return this.count;
		}

		@Override
		public int read() throws IOException {
			int value = super.read();
			if (value != -1) {
				this.count++;
			}
			return value;
		}

		@Override
		public int read(byte[] bytes, int offset, int length) throws IOException {
			int read = super.read(bytes, offset, length);
			if (read > 0) {
				this.count += read;
			}
			return read;
		}

		@Override
		public long skip(long amount) throws IOException {
			long skipped = super.skip(amount);
			this.count += skipped;
			return skipped;
		}
	}

	private static final class MissingSnapshotException extends IOException {
	}

	public interface Labeled {
		String label();
	}

	public interface Filter extends Labeled {
		@Nullable String condition();
	}

	public enum Sort implements Labeled {
		IP_PORT("IP / port",
			Comparator.comparing(r -> ipKey(r.address()))),
		MOTD("MOTD",
			Comparator.comparing(r -> r.motd().toLowerCase(Locale.ROOT))),
		PLAYERS("Players",
			Comparator.comparingInt(ServerRecord::playersOnline)),
		VERSION("Version",
			Comparator.comparing(ServerRecord::version,
				(a, b) -> compareVersionKeys(versionKey(a), versionKey(b)))),
		CRACKED("Cracked",
			Comparator.comparing(r -> r.cracked() ? "1" : "0")),
		WHITELIST("Whitelist",
			Comparator.comparing(r -> r.whitelist().toLowerCase(Locale.ROOT))),
		ONLINE_NAMES("Online names",
			Comparator.comparing(r -> r.playersNowText().toLowerCase(Locale.ROOT))),
		SEEN_NAMES("Seen names",
			Comparator.comparing(r -> r.playersEverText().toLowerCase(Locale.ROOT))),
		FIRST_SEEN("First seen",
			Comparator.comparingLong(r -> minuteKey(r.firstSeenEpochSeconds()))),
		LAST_SEEN("Last seen",
			Comparator.comparingLong(r -> minuteKey(r.lastSeenEpochSeconds()))),
		TIMES_SEEN("Times seen",
			Comparator.comparingInt(ServerRecord::timesSeen));

		private final String label;
		private final Comparator<ServerRecord> comparator;

		Sort(String label, Comparator<ServerRecord> comparator) {
			this.label = label;
			this.comparator = comparator;
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

	public record Query(String search, PlayersFilter players, AuthFilter auth, WhitelistFilter whitelist) {
		public static final Query DEFAULT = new Query("", PlayersFilter.ANY, AuthFilter.ANY, WhitelistFilter.ANY);

		public Query withSearch(String search) {
			return new Query(search, this.players, this.auth, this.whitelist);
		}

		public Query withPlayers(PlayersFilter players) {
			return new Query(this.search, players, this.auth, this.whitelist);
		}

		public Query withAuth(AuthFilter auth) {
			return new Query(this.search, this.players, auth, this.whitelist);
		}

		public Query withWhitelist(WhitelistFilter whitelist) {
			return new Query(this.search, this.players, this.auth, whitelist);
		}
	}

	public record QueryResult(List<ServerRecord> rows) {
	}

	private record SchemaObject(String type, String name, String table, @Nullable String sql) {
	}
}
