package com.mcdbbrowser;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The same small search language as the Rust and web viewers.
 *
 * The compiler emits a WHERE fragment with ? placeholders and the matching
 * parameter list; identifiers only come from the fixed tables below, so user
 * input can never change the query shape.
 */
final class SearchQuery {
	private static final String NOW = "strftime('%s','now')";
	private static final List<String> BARE_COLUMNS = List.of(
		"ip_port", "motd", "version", "whitelist", "players_now", "players_ever");
	private static final String[] OPERATORS = {
		">=", "<=", "!=", "!~", "~", "=", ">", "<", ":", "^"
	};

	private SearchQuery() {
	}

	record Result(String where, List<Object> params) {
	}

	private record Split(String field, String op, String value) {
	}

	static Result compile(String input) {
		List<String> clauses = new ArrayList<>();
		List<Object> params = new ArrayList<>();
		for (String term : tokenize(input == null ? "" : input)) {
			boolean negate = term.length() > 1 && term.charAt(0) == '-';
			String body = negate ? term.substring(1) : term;
			if (body.isEmpty()) {
				continue;
			}
			Split split = splitTerm(body);
			String clause = compileTerm(split, body, params);
			clauses.add(negate ? "NOT " + clause : clause);
		}
		if (clauses.isEmpty()) {
			return new Result("", params);
		}
		return new Result("WHERE " + String.join(" AND ", clauses), params);
	}

	private static String compileTerm(Split split, String body, List<Object> params) {
		String field = split.field();
		String op = split.op();
		String value = split.value();

		if (field == null) {
			return bareClause(value, params);
		}

		String textColumn = textColumn(field);
		if (textColumn != null) {
			boolean negated = op.equals("!=") || op.equals("!~");
			if (textColumn.equals("cracked")
					&& (op.equals("=") || op.equals(":") || op.equals("~")
						|| op.equals("!=") || op.equals("!~"))) {
				Long cracked = crackedValue(value);
				if (cracked != null) {
					params.add(cracked);
					return "(cracked " + (negated ? "!=" : "=") + " ?)";
				}
			}
			String status = textColumn.equals("whitelist")
				&& (op.equals("=") || op.equals(":") || op.equals("!=") || op.equals("!~"))
				? whitelistPrefix(value) : null;
			String pattern;
			if (status != null) {
				pattern = status;
			} else if (op.equals("^") || (textColumn.equals("ip_port") && op.equals(":"))) {
				pattern = prefixParam(value);
			} else {
				pattern = likeParam(value);
			}
			params.add(pattern);
			return "(" + textColumn + (negated ? " NOT LIKE" : " LIKE")
				+ " ? ESCAPE '\\')";
		}

		String numericColumn = numericColumn(field);
		if (numericColumn != null) {
			Long number = parseLong(value);
			if (number == null) {
				throw new IllegalArgumentException(field + " needs a number (got \"" + value + "\")");
			}
			String sqlOp = compareOp(op);
			if (sqlOp == null) {
				throw new IllegalArgumentException(field + " needs a number (got \"" + value + "\")");
			}
			params.add(number);
			return "(" + numericColumn + " " + sqlOp + " ?)";
		}

		String timeColumn = timeColumn(field);
		if (timeColumn != null) {
			Long seconds = parseDuration(value);
			if (seconds != null) {
				String sqlOp = switch (op) {
					case "<" -> ">";
					case "<=" -> ">=";
					case ">" -> "<";
					case ">=" -> "<=";
					case "=", ":", "~" -> "=";
					case "!=", "!~" -> "!=";
					default -> null;
				};
				if (sqlOp == null) {
					throw new IllegalArgumentException(field + " needs a duration/epoch (got \"" + value + "\")");
				}
				params.add(seconds);
				return "(" + timeColumn + " " + sqlOp + " " + NOW + " - ?)";
			}
			Long epoch = parseLong(value);
			String sqlOp = compareOp(op);
			if (epoch == null || sqlOp == null) {
				throw new IllegalArgumentException(field + " needs a duration/epoch (got \"" + value + "\")");
			}
			params.add(epoch);
			return "(" + timeColumn + " " + sqlOp + " ?)";
		}

		if (field.equals("names") || field.equals("player") || field.equals("players_sample")) {
			String like = likeParam(value);
			params.add(like);
			params.add(like);
			return "(players_now LIKE ? ESCAPE '\\' OR players_ever LIKE ? ESCAPE '\\')";
		}

		if (op.equals(":")) {
			// Not a known field: search the literal text (URLs, "C:\path").
			return bareClause(body, params);
		}
		throw new IllegalArgumentException("unknown field \"" + field
			+ "\" (ip, motd, version, cracked, whitelist, source, players, max, "
			+ "seen, first, times, protocol, names)");
	}

	private static String compareOp(String op) {
		return switch (op) {
			case "=", ":", "~" -> "=";
			case "!=", "!~" -> "!=";
			case ">" -> ">";
			case ">=" -> ">=";
			case "<" -> "<";
			case "<=" -> "<=";
			default -> null;
		};
	}

	private static String textColumn(String field) {
		return switch (field) {
			case "ip", "ip_port", "host" -> "ip_port";
			case "motd", "description" -> "motd";
			case "version" -> "version";
			case "cracked" -> "cracked";
			case "whitelist", "wl" -> "whitelist";
			case "source" -> "last_source";
			default -> null;
		};
	}

	private static String numericColumn(String field) {
		return switch (field) {
			case "players", "online" -> "players_online";
			case "max", "max_players" -> "max_players";
			case "times", "times_seen" -> "times_seen";
			case "protocol" -> "protocol";
			case "port" -> "port";
			default -> null;
		};
	}

	private static String timeColumn(String field) {
		return switch (field) {
			case "seen", "last_seen", "last" -> "last_seen";
			case "first", "first_seen" -> "first_seen";
			default -> null;
		};
	}

	private static Long crackedValue(String value) {
		return switch (value.trim().toLowerCase(Locale.ROOT)) {
			case "yes", "true", "1" -> 1L;
			case "no", "false", "0" -> 0L;
			default -> null;
		};
	}

	private static String whitelistPrefix(String value) {
		return switch (value.trim().toLowerCase(Locale.ROOT)) {
			case "yes", "true", "whitelisted" -> "Whitelisted:%";
			case "no", "false", "not whitelisted" -> "Not Whitelisted:%";
			case "unknown" -> "Unknown:%";
			default -> null;
		};
	}

	private static Long parseDuration(String value) {
		String text = value.trim();
		if (text.length() < 2) {
			return null;
		}
		char suffix = text.charAt(text.length() - 1);
		long multiplier = switch (suffix) {
			case 's' -> 1L;
			case 'm' -> 60L;
			case 'h' -> 3600L;
			case 'd' -> 86400L;
			case 'w' -> 7L * 86400L;
			default -> 0L;
		};
		if (multiplier == 0L) {
			return null;
		}
		Long number = parseLong(text.substring(0, text.length() - 1));
		return number == null ? null : number * multiplier;
	}

	private static Long parseLong(String value) {
		try {
			return Long.parseLong(value.trim());
		} catch (NumberFormatException e) {
			return null;
		}
	}

	private static String bareClause(String value, List<Object> params) {
		List<String> parts = new ArrayList<>(BARE_COLUMNS.size());
		for (String column : BARE_COLUMNS) {
			params.add(likeParam(value));
			parts.add(column + " LIKE ? ESCAPE '\\'");
		}
		return "(" + String.join(" OR ", parts) + ")";
	}

	private static String likeParam(String value) {
		StringBuilder out = new StringBuilder(value.length() + 2).append('%');
		for (int i = 0; i < value.length(); i++) {
			char ch = value.charAt(i);
			if (ch == '%' || ch == '_' || ch == '\\') {
				out.append('\\');
			}
			out.append(ch);
		}
		return out.append('%').toString();
	}

	private static String prefixParam(String value) {
		StringBuilder out = new StringBuilder(value.length() + 1);
		for (int i = 0; i < value.length(); i++) {
			char ch = value.charAt(i);
			if (ch == '%' || ch == '_' || ch == '\\') {
				out.append('\\');
			}
			out.append(ch);
		}
		return out.append('%').toString();
	}

	private static List<String> tokenize(String input) {
		List<String> out = new ArrayList<>();
		StringBuilder current = new StringBuilder();
		boolean quoted = false;
		boolean escape = false;
		for (int i = 0; i < input.length(); i++) {
			char ch = input.charAt(i);
			if (escape) {
				current.append(ch);
				escape = false;
			} else if (ch == '\\') {
				escape = true;
			} else if (ch == '"') {
				quoted = !quoted;
			} else if (Character.isWhitespace(ch) && !quoted) {
				if (current.length() > 0) {
					out.add(current.toString());
					current.setLength(0);
				}
			} else {
				current.append(ch);
			}
		}
		if (quoted) {
			throw new IllegalArgumentException("unbalanced quote");
		}
		if (current.length() > 0) {
			out.add(current.toString());
		}
		return out;
	}

	private static Split splitTerm(String term) {
		for (int i = 0; i < term.length(); i++) {
			char ch = term.charAt(i);
			if (isAsciiWord(ch)) {
				continue;
			}
			String rest = term.substring(i);
			for (String op : OPERATORS) {
				if (rest.startsWith(op)) {
					String field = term.substring(0, i);
					if (field.isEmpty()) {
						break;
					}
					return new Split(field.toLowerCase(Locale.ROOT), op,
						unquote(rest.substring(op.length())));
				}
			}
			break;
		}
		return new Split(null, "", unquote(term));
	}

	private static boolean isAsciiWord(char ch) {
		return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
			|| (ch >= '0' && ch <= '9') || ch == '_';
	}

	private static String unquote(String value) {
		String text = value.trim();
		if (text.length() >= 2 && text.startsWith("\"") && text.endsWith("\"")) {
			return text.substring(1, text.length() - 1);
		}
		return text;
	}
}
