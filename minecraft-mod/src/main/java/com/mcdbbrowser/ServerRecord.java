package com.mcdbbrowser;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.jspecify.annotations.Nullable;

public record ServerRecord(
	String address,
	String motd,
	int playersOnline,
	int maxPlayers,
	String version,
	int protocol,
	boolean cracked,
	String whitelist,
	double firstSeenEpochSeconds,
	double lastSeenEpochSeconds,
	int timesSeen,
	String playersNowJson,
	String playersEverJson
) {
	static ServerRecord fromRow(ResultSet rs) throws SQLException {
		return new ServerRecord(
			rs.getString("ip_port"),
			nullToEmpty(rs.getString("motd")),
			rs.getInt("players_online"),
			rs.getInt("max_players"),
			nullToEmpty(rs.getString("version")),
			rs.getInt("protocol"),
			rs.getBoolean("cracked"),
			nullToEmpty(rs.getString("whitelist")),
			rs.getDouble("first_seen"),
			rs.getDouble("last_seen"),
			rs.getInt("times_seen"),
			nullToEmpty(rs.getString("players_now")),
			nullToEmpty(rs.getString("players_ever"))
		);
	}

	private static String nullToEmpty(@Nullable String s) {
		return s == null ? "" : s;
	}

	ServerRecord withWhitelist(String newWhitelist) {
		return new ServerRecord(this.address, this.motd, this.playersOnline, this.maxPlayers,
			this.version, this.protocol, this.cracked, newWhitelist == null ? "" : newWhitelist,
			this.firstSeenEpochSeconds, this.lastSeenEpochSeconds, this.timesSeen,
			this.playersNowJson, this.playersEverJson);
	}

	public WhitelistState whitelistState() {
		if (this.whitelist.startsWith("Not Whitelisted")) {
			return WhitelistState.OPEN;
		} else if (this.whitelist.startsWith("Whitelisted")) {
			return WhitelistState.WHITELISTED;
		} else {
			return WhitelistState.UNKNOWN;
		}
	}

	public List<String> playersNow() {
		return parsePlayerNames(this.playersNowJson);
	}

	public List<String> playersEver() {
		return parsePlayerNames(this.playersEverJson);
	}

	public String playersNowText() {
		return String.join(", ", playersNow());
	}

	public String playersEverText() {
		return String.join(", ", playersEver());
	}

	static List<String> parsePlayerNames(@Nullable String json) {
		List<String> names = new ArrayList<>();
		if (json == null || json.isBlank()) {
			return names;
		}

		try {
			for (JsonElement name : JsonParser.parseString(json).getAsJsonArray()) {
				names.add(name.getAsString());
			}
		} catch (RuntimeException e) {
			McdbBrowserClient.LOGGER.debug("Malformed player list", e);
		}
		return names;
	}

	public enum WhitelistState {
		OPEN,
		WHITELISTED,
		UNKNOWN
	}
}
