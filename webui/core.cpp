// Web UI core: SQLite + the viewer's search/sort/format logic, compiled to
// WebAssembly with Emscripten.  The browser fetches a consistent snapshot of
// servers.db, writes it to the in-memory filesystem, and calls these exports.
//
// The table only asks for the cells it is drawing, so 100k+ rows stay light:
// the rows live here in C++ and JavaScript gets one UTF-8 string per cell.

#include <emscripten.h>

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <strings.h>

#include <chrono>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace {

struct Row {
    std::string ip;
    std::string motd;
    long long players = 0;
    long long max_players = 0;
    std::string version;
    std::string cracked;
    std::string whitelist;
    std::string names_now;
    std::string names_ever;
    double first_seen = 0.0;
    double last_seen = 0.0;
    long long times_seen = 0;
    long long protocol = 0;
};

sqlite3 *g_db = nullptr;
std::vector<Row> g_rows;
long long g_total = 0;
long long g_load_ms = 0;
std::string g_scratch;
std::string g_error;

// ---------------------------------------------------------------- text helpers

bool is_hidden(uint32_t cp) {
    return cp == 0x061c || cp == 0x180e || cp == 0x200b || cp == 0x200e ||
           cp == 0x200f || (cp >= 0x202a && cp <= 0x202e) ||
           (cp >= 0x2060 && cp <= 0x206f) || cp == 0xfeff;
}

void append_utf8(std::string &out, uint32_t cp) {
    if (cp <= 0x7f) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7ff) {
        out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp <= 0xffff) {
        out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
        out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
}

// Decode the next UTF-8 code point; invalid bytes are passed through as
// replacement code points so display never loses or corrupts valid text.
uint32_t next_cp(const std::string &s, size_t &i) {
    unsigned char b = static_cast<unsigned char>(s[i++]);
    if (b < 0x80) {
        return b;
    }
    int extra = 0;
    uint32_t cp = 0;
    if ((b & 0xe0) == 0xc0) {
        extra = 1;
        cp = b & 0x1f;
    } else if ((b & 0xf0) == 0xe0) {
        extra = 2;
        cp = b & 0x0f;
    } else if ((b & 0xf8) == 0xf0) {
        extra = 3;
        cp = b & 0x07;
    } else {
        return 0xfffd;
    }
    if (i + extra > s.size()) {
        i = s.size();
        return 0xfffd;
    }
    for (int n = 0; n < extra; ++n) {
        unsigned char c = static_cast<unsigned char>(s[i++]);
        if ((c & 0xc0) != 0x80) {
            return 0xfffd;
        }
        cp = (cp << 6) | (c & 0x3f);
    }
    return cp;
}

// Single-line table cell: controls/bidi stripped, newlines become spaces.
std::string clean_display(const std::string &value) {
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size();) {
        uint32_t cp = next_cp(value, i);
        if (cp == '\n' || cp == '\r' || cp == '\t') {
            out.push_back(' ');
        } else if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || is_hidden(cp)) {
            continue;
        } else {
            append_utf8(out, cp);
        }
    }
    return out;
}

// Detail pane: keep newlines, expand tabs, strip other controls/bidi.
std::string clean_multiline(const std::string &value) {
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size();) {
        uint32_t cp = next_cp(value, i);
        if (cp == '\n') {
            out.push_back('\n');
        } else if (cp == '\t') {
            out += "    ";
        } else if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || is_hidden(cp)) {
            continue;
        } else {
            append_utf8(out, cp);
        }
    }
    return out;
}

std::string trim(const std::string &s) {
    size_t a = 0;
    size_t b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) {
        ++a;
    }
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) {
        --b;
    }
    return s.substr(a, b - a);
}

std::string lower_text(const std::string &s) {
    std::string out = s;
    for (char &c : out) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u >= 'A' && u <= 'Z') {
            c = static_cast<char>(u + ('a' - 'A'));
        }
    }
    return out;
}

// ------------------------------------------------------------- JSON name list

bool parse_json_string(const std::string &s, size_t &i, std::string &out) {
    if (i >= s.size() || s[i] != '"') {
        return false;
    }
    ++i;
    while (i < s.size()) {
        char c = s[i++];
        if (c == '"') {
            return true;
        }
        if (c != '\\') {
            out.push_back(c);
            continue;
        }
        if (i >= s.size()) {
            return false;
        }
        char esc = s[i++];
        switch (esc) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
            auto hex4 = [&](uint32_t &value) {
                if (i + 4 > s.size()) {
                    return false;
                }
                value = 0;
                for (int n = 0; n < 4; ++n) {
                    char h = s[i++];
                    int d = (h >= '0' && h <= '9') ? h - '0'
                          : (h >= 'a' && h <= 'f') ? h - 'a' + 10
                          : (h >= 'A' && h <= 'F') ? h - 'A' + 10
                                                   : -1;
                    if (d < 0) {
                        return false;
                    }
                    value = (value << 4) | static_cast<uint32_t>(d);
                }
                return true;
            };
            uint32_t cp = 0;
            if (!hex4(cp)) {
                return false;
            }
            if (cp >= 0xd800 && cp <= 0xdbff && i + 6 <= s.size() &&
                s[i] == '\\' && s[i + 1] == 'u') {
                size_t save = i;
                i += 2;
                uint32_t low = 0;
                if (hex4(low) && low >= 0xdc00 && low <= 0xdfff) {
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                } else {
                    i = save;
                }
            }
            append_utf8(out, cp);
            break;
        }
        default:
            return false;
        }
    }
    return false;
}

bool parse_json_names(const std::string &raw, std::vector<std::string> &names) {
    size_t i = 0;
    auto ws = [&]() {
        while (i < raw.size() && std::isspace(static_cast<unsigned char>(raw[i]))) {
            ++i;
        }
    };
    ws();
    if (i >= raw.size() || raw[i] != '[') {
        return false;
    }
    ++i;
    ws();
    if (i < raw.size() && raw[i] == ']') {
        return true;
    }
    while (i < raw.size()) {
        std::string name;
        if (!parse_json_string(raw, i, name)) {
            return false;
        }
        if (!name.empty()) {
            names.push_back(std::move(name));
        }
        ws();
        if (i < raw.size() && raw[i] == ',') {
            ++i;
            ws();
            continue;
        }
        if (i < raw.size() && raw[i] == ']') {
            return true;
        }
        return false;
    }
    return false;
}

std::string names_of(const std::string &raw) {
    std::vector<std::string> names;
    if (parse_json_names(raw, names)) {
        if (names.empty()) {
            return "-";
        }
        std::string out;
        for (size_t i = 0; i < names.size(); ++i) {
            if (i) {
                out += ", ";
            }
            out += clean_display(names[i]);
        }
        return out;
    }
    std::string text = clean_display(trim(raw));
    return (text.empty() || text == "[]") ? "-" : text;
}

// ------------------------------------------------------------------- sorting

struct IpKey {
    bool v4 = false;
    uint32_t a = 0;
    uint32_t b = 0;
    uint32_t c = 0;
    uint32_t d = 0;
    uint32_t port = 0;
    std::string other;

    bool operator<(const IpKey &o) const {
        if (v4 != o.v4) {
            return v4;
        }
        if (v4) {
            if (a != o.a) return a < o.a;
            if (b != o.b) return b < o.b;
            if (c != o.c) return c < o.c;
            if (d != o.d) return d < o.d;
            return port < o.port;
        }
        if (other != o.other) return other < o.other;
        return port < o.port;
    }
};

using SortKey = std::variant<IpKey, std::string, long long, std::vector<uint64_t>>;

IpKey ip_key(const std::string &value) {
    IpKey key;
    size_t colons = static_cast<size_t>(std::count(value.begin(), value.end(), ':'));
    std::string host = value;
    uint32_t port = 0;
    if (colons == 1) {
        size_t pos = value.find(':');
        host = value.substr(0, pos);
        std::string port_s = value.substr(pos + 1);
        try {
            size_t used = 0;
            unsigned long n = std::stoul(port_s, &used);
            if (used == port_s.size() && n <= 0xffffffffUL) {
                port = static_cast<uint32_t>(n);
            } else {
                host = value;
            }
        } catch (...) {
            host = value;
        }
    }
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t dot = host.find('.', start);
        if (dot == std::string::npos) {
            parts.push_back(host.substr(start));
            break;
        }
        parts.push_back(host.substr(start, dot - start));
        start = dot + 1;
    }
    bool v4 = parts.size() == 4;
    for (const std::string &part : parts) {
        if (part.empty()) {
            v4 = false;
            break;
        }
        for (char c : part) {
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                v4 = false;
                break;
            }
        }
        if (!v4) {
            break;
        }
    }
    if (v4) {
        try {
            key.v4 = true;
            key.a = static_cast<uint32_t>(std::stoul(parts[0]));
            key.b = static_cast<uint32_t>(std::stoul(parts[1]));
            key.c = static_cast<uint32_t>(std::stoul(parts[2]));
            key.d = static_cast<uint32_t>(std::stoul(parts[3]));
            key.port = port;
            return key;
        } catch (...) {
            key.v4 = true;
            key.port = port;
            return key;
        }
    }
    key.other = host;
    key.port = port;
    return key;
}

std::vector<uint64_t> version_key(const std::string &value_raw) {
    std::string value = trim(value_raw);
    std::vector<uint64_t> out;
    size_t start = 0;
    while (true) {
        size_t dot = value.find('.', start);
        std::string token = value.substr(start, dot == std::string::npos
                                                    ? std::string::npos
                                                    : dot - start);
        if (!token.empty()) {
            bool digits = true;
            for (char c : token) {
                if (!std::isdigit(static_cast<unsigned char>(c))) {
                    digits = false;
                    break;
                }
            }
            if (digits) {
                try {
                    out.push_back(std::stoull(token));
                } catch (...) {
                    out.push_back(0);
                }
            } else {
                bool found = false;
                size_t p = 0;
                while (p < token.size()) {
                    while (p < token.size() &&
                           !std::isdigit(static_cast<unsigned char>(token[p]))) {
                        ++p;
                    }
                    size_t q = p;
                    while (q < token.size() &&
                           std::isdigit(static_cast<unsigned char>(token[q]))) {
                        ++q;
                    }
                    if (q > p) {
                        try {
                            out.push_back(std::stoull(token.substr(p, q - p)));
                        } catch (...) {
                            out.push_back(0);
                        }
                        found = true;
                    }
                    p = q;
                }
                if (!found) {
                    out.push_back(0);
                }
            }
        }
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    if (out.empty()) {
        out.push_back(0);
    }
    return out;
}

long long minute_key(double epoch) {
    return epoch > 0.0 ? static_cast<long long>(epoch / 60.0) : 0;
}

SortKey sort_key(const Row &row, const std::string &column) {
    if (column == "ip_port") return ip_key(row.ip);
    if (column == "motd") return lower_text(row.motd);
    if (column == "players") return row.players;
    if (column == "version") return version_key(row.version);
    if (column == "cracked") return lower_text(row.cracked);
    if (column == "whitelist") return lower_text(row.whitelist);
    if (column == "online_names") return lower_text(names_of(row.names_now));
    if (column == "seen_names") return lower_text(names_of(row.names_ever));
    if (column == "first_seen") return minute_key(row.first_seen);
    if (column == "times_seen") return row.times_seen;
    return minute_key(row.last_seen);
}

bool valid_sort_column(const std::string &column) {
    return column == "ip_port" || column == "motd" || column == "players" ||
           column == "version" || column == "cracked" || column == "whitelist" ||
           column == "online_names" || column == "seen_names" ||
           column == "first_seen" || column == "last_seen" ||
           column == "times_seen";
}

void sort_by_column(const std::string &column, bool desc) {
    if (!valid_sort_column(column) || g_rows.empty()) {
        return;
    }
    std::vector<std::pair<SortKey, Row>> keyed;
    keyed.reserve(g_rows.size());
    for (Row &row : g_rows) {
        keyed.emplace_back(sort_key(row, column), std::move(row));
    }
    std::stable_sort(keyed.begin(), keyed.end(),
                     [desc](const auto &a, const auto &b) {
                         return desc ? b.first < a.first : a.first < b.first;
                     });
    g_rows.clear();
    g_rows.reserve(keyed.size());
    for (auto &entry : keyed) {
        g_rows.push_back(std::move(entry.second));
    }
}

// -------------------------------------------------------------------- search

struct Param {
    bool text = false;
    std::string value;
    sqlite3_int64 number = 0;
};

std::string like_param(const std::string &value) {
    std::string out;
    out.reserve(value.size() + 2);
    for (char c : value) {
        if (c == '%' || c == '_' || c == '\\') {
            out.push_back('\\');
        }
        out.push_back(c);
    }
    return "%" + out + "%";
}

std::string prefix_param(const std::string &value) {
    std::string out;
    out.reserve(value.size() + 1);
    for (char c : value) {
        if (c == '%' || c == '_' || c == '\\') {
            out.push_back('\\');
        }
        out.push_back(c);
    }
    return out + "%";
}

std::string unquote(const std::string &value) {
    std::string v = trim(value);
    if (v.size() >= 2 && v.front() == '"' && v.back() == '"') {
        return v.substr(1, v.size() - 2);
    }
    return v;
}

bool tokenize(const std::string &input, std::vector<std::string> &out) {
    std::string cur;
    bool quoted = false;
    bool escape = false;
    for (char c : input) {
        if (escape) {
            cur.push_back(c);
            escape = false;
            continue;
        }
        if (c == '\\') {
            escape = true;
        } else if (c == '"') {
            quoted = !quoted;
        } else if (std::isspace(static_cast<unsigned char>(c)) && !quoted) {
            if (!cur.empty()) {
                out.push_back(std::move(cur));
                cur.clear();
            }
        } else {
            cur.push_back(c);
        }
    }
    if (quoted) {
        return false;
    }
    if (!cur.empty()) {
        out.push_back(std::move(cur));
    }
    return true;
}

bool parse_duration(const std::string &raw, long long &seconds) {
    if (raw.empty()) {
        return false;
    }
    char unit = raw.back();
    long long mult = 0;
    if (unit == 's') mult = 1;
    else if (unit == 'm') mult = 60;
    else if (unit == 'h') mult = 3600;
    else if (unit == 'd') mult = 86400;
    else if (unit == 'w') mult = 7 * 86400;
    if (!mult) {
        return false;
    }
    std::string num = raw.substr(0, raw.size() - 1);
    try {
        size_t used = 0;
        long long n = std::stoll(num, &used);
        if (used != num.size()) {
            return false;
        }
        seconds = n * mult;
        return true;
    } catch (...) {
        return false;
    }
}

const char *text_column(const std::string &field) {
    if (field == "ip" || field == "ip_port" || field == "host") return "ip_port";
    if (field == "motd" || field == "description") return "motd";
    if (field == "version") return "version";
    if (field == "cracked") return "cracked";
    if (field == "whitelist" || field == "wl") return "whitelist";
    if (field == "source") return "last_source";
    return nullptr;
}

const char *numeric_column(const std::string &field) {
    if (field == "players" || field == "online") return "players_online";
    if (field == "max" || field == "max_players") return "max_players";
    if (field == "times" || field == "times_seen") return "times_seen";
    if (field == "protocol") return "protocol";
    if (field == "port") return "port";
    return nullptr;
}

const char *time_column(const std::string &field) {
    if (field == "seen" || field == "last_seen" || field == "last") return "last_seen";
    if (field == "first" || field == "first_seen") return "first_seen";
    return nullptr;
}

void push_text(std::vector<Param> &params, const std::string &value) {
    Param p;
    p.text = true;
    p.value = value;
    params.push_back(std::move(p));
}

void push_int(std::vector<Param> &params, long long value) {
    Param p;
    p.number = value;
    params.push_back(std::move(p));
}

bool parse_i64(const std::string &raw, long long &value) {
    std::string v = trim(raw);
    try {
        size_t used = 0;
        value = std::stoll(v, &used);
        return used == v.size();
    } catch (...) {
        return false;
    }
}

std::string cmp_sql(const std::string &op, const std::string &col,
                    const std::string &value, std::vector<Param> &params,
                    bool &ok) {
    long long number = 0;
    if (!parse_i64(value, number)) {
        ok = false;
        return {};
    }
    std::string sql_op;
    if (op == "=" || op == ":" || op == "~") sql_op = "=";
    else if (op == "!=" || op == "!~") sql_op = "!=";
    else if (op == ">") sql_op = ">";
    else if (op == ">=") sql_op = ">=";
    else if (op == "<") sql_op = "<";
    else if (op == "<=") sql_op = "<=";
    else {
        ok = false;
        return {};
    }
    push_int(params, number);
    ok = true;
    return "(" + col + " " + sql_op + " ?)";
}

std::string age_sql(const std::string &op, const std::string &col,
                    const std::string &value, std::vector<Param> &params,
                    bool &ok) {
    long long seconds = 0;
    if (!parse_duration(value, seconds)) {
        long long ts = 0;
        if (!parse_i64(value, ts)) {
            ok = false;
            return {};
        }
        std::string sql_op;
        if (op == "=" || op == ":" || op == "~") sql_op = "=";
        else if (op == "!=" || op == "!~") sql_op = "!=";
        else if (op == ">") sql_op = ">";
        else if (op == ">=") sql_op = ">=";
        else if (op == "<") sql_op = "<";
        else if (op == "<=") sql_op = "<=";
        else {
            ok = false;
            return {};
        }
        push_int(params, ts);
        ok = true;
        return "(" + col + " " + sql_op + " ?)";
    }
    std::string sql_op;
    if (op == "<") sql_op = ">";
    else if (op == "<=") sql_op = ">=";
    else if (op == ">") sql_op = "<";
    else if (op == ">=") sql_op = "<=";
    else if (op == "=" || op == ":" || op == "~") sql_op = "=";
    else if (op == "!=" || op == "!~") sql_op = "!=";
    else {
        ok = false;
        return {};
    }
    push_int(params, seconds);
    ok = true;
    return "(" + col + " " + sql_op + " strftime('%s','now') - ?)";
}

const char *whitelist_prefix(const std::string &value) {
    std::string v = lower_text(trim(value));
    if (v == "yes" || v == "true" || v == "whitelisted") return "Whitelisted:%";
    if (v == "no" || v == "false" || v == "not whitelisted") return "Not Whitelisted:%";
    if (v == "unknown") return "Unknown:%";
    return nullptr;
}

const char *const BARE_COLUMNS[] = {
    "ip_port", "motd", "version", "whitelist", "players_now", "players_ever",
};

std::string bare_clause(const std::string &value, std::vector<Param> &params) {
    std::string like = like_param(value);
    std::string sql = "(";
    for (size_t i = 0; i < sizeof(BARE_COLUMNS) / sizeof(BARE_COLUMNS[0]); ++i) {
        if (i) sql += " OR ";
        sql += std::string(BARE_COLUMNS[i]) + " LIKE ? ESCAPE '\\'";
        push_text(params, like);
    }
    sql += ")";
    return sql;
}

bool split_term(const std::string &term, std::string &field, std::string &op,
                std::string &value) {
    static const char *const OPS[] = {">=", "<=", "!=", "!~", "~", "=", ">", "<", ":", "^"};
    for (size_t i = 0; i < term.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(term[i]);
        if (std::isalnum(c) || c == '_') {
            continue;
        }
        std::string rest = term.substr(i);
        for (const char *candidate : OPS) {
            std::string token(candidate);
            if (rest.rfind(token, 0) == 0) {
                std::string f = term.substr(0, i);
                if (f.empty()) {
                    break;
                }
                field = lower_text(f);
                op = token;
                value = unquote(rest.substr(token.size()));
                return true;
            }
        }
        break;
    }
    field.clear();
    op.clear();
    value = unquote(term);
    return true;
}

bool compile_search(const std::string &input, std::string &where_sql,
                    std::vector<Param> &params, std::string &error) {
    std::vector<std::string> terms;
    if (!tokenize(input, terms)) {
        error = "unbalanced quote";
        return false;
    }
    std::vector<std::string> clauses;
    for (std::string &term : terms) {
        bool negate = term.size() > 1 && term.front() == '-';
        std::string body = negate ? term.substr(1) : term;
        if (body.empty()) {
            continue;
        }
        std::string field;
        std::string op;
        std::string value;
        split_term(body, field, op, value);
        std::string clause;
        if (field.empty()) {
            clause = bare_clause(value, params);
        } else if (const char *col = text_column(field)) {
            bool negated = op == "!=" || op == "!~";
            const char *status = nullptr;
            if (std::string(col) == "whitelist" &&
                (op == "=" || op == ":" || op == "!=" || op == "!~")) {
                status = whitelist_prefix(value);
            }
            std::string pattern;
            if (status) {
                pattern = status;
            } else if (op == "^" || (std::string(col) == "ip_port" && op == ":")) {
                pattern = prefix_param(value);
            } else {
                pattern = like_param(value);
            }
            push_text(params, pattern);
            clause = std::string("(") + col + (negated ? " NOT LIKE ? ESCAPE '\\'" : " LIKE ? ESCAPE '\\'") + ")";
        } else if (const char *col = numeric_column(field)) {
            bool ok = false;
            clause = cmp_sql(op, col, value, params, ok);
            if (!ok) {
                error = field + " needs a number (got \"" + value + "\")";
                return false;
            }
        } else if (const char *col = time_column(field)) {
            bool ok = false;
            clause = age_sql(op, col, value, params, ok);
            if (!ok) {
                error = field + " needs a duration/epoch (got \"" + value + "\")";
                return false;
            }
        } else if (field == "names" || field == "player" || field == "players_sample") {
            std::string like = like_param(value);
            push_text(params, like);
            push_text(params, like);
            clause = "(players_now LIKE ? ESCAPE '\\' OR players_ever LIKE ? ESCAPE '\\')";
        } else if (op == ":") {
            clause = bare_clause(body, params);
        } else {
            error = "unknown field \"" + field + "\" (ip, motd, version, cracked, "
                    "whitelist, source, players, max, seen, first, times, "
                    "protocol, names)";
            return false;
        }
        clauses.push_back(negate ? "NOT " + clause : clause);
    }
    if (clauses.empty()) {
        where_sql.clear();
    } else {
        where_sql = "WHERE ";
        for (size_t i = 0; i < clauses.size(); ++i) {
            if (i) where_sql += " AND ";
            where_sql += clauses[i];
        }
    }
    return true;
}

// ------------------------------------------------------------------- SQLite

bool has_column(const char *name) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, "PRAGMA table_info(servers)", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    bool found = false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *col = sqlite3_column_text(stmt, 1);
        if (col && strcasecmp(reinterpret_cast<const char *>(col), name) == 0) {
            found = true;
            break;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

std::string col_or(const char *name, const char *fallback) {
    return has_column(name) ? std::string("COALESCE(") + name + "," + fallback + ")"
                            : std::string(fallback);
}

std::string text_col(sqlite3_stmt *stmt, int index) {
    const unsigned char *text = sqlite3_column_text(stmt, index);
    return text ? reinterpret_cast<const char *>(text) : "";
}

std::string timestamp_text(double epoch) {
    if (epoch <= 0.0) {
        return "-";
    }
    std::time_t t = static_cast<std::time_t>(epoch);
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tmv);
    return buf;
}

std::string detail_text(const Row &row) {
    std::string out;
    out.reserve(512);
    out += clean_multiline(row.ip) + "\n\n";
    std::string motd = clean_multiline(row.motd);
    out += "MOTD:        " + (motd.empty() ? std::string("-") : motd) + "\n";
    out += "Players:     " + std::to_string(row.players) + "/" +
           std::to_string(row.max_players) + " (seen " +
           std::to_string(row.times_seen) + " time(s))\n";
    std::string version = clean_multiline(row.version);
    out += "Version:     " + (version.empty() ? std::string("-") : version) +
           " (protocol " + std::to_string(row.protocol) + ")\n";
    std::string cracked = clean_multiline(row.cracked);
    out += "Cracked:     " + (cracked.empty() ? std::string("-") : cracked) + "\n";
    std::string whitelist = clean_multiline(row.whitelist);
    out += "Whitelist:   " + (whitelist.empty() ? std::string("-") : whitelist) + "\n";
    out += "First seen:  " + timestamp_text(row.first_seen) + "\n";
    out += "Last seen:   " + timestamp_text(row.last_seen) + "\n\n";
    out += "Online now:  " + names_of(row.names_now) + "\n";
    out += "Ever seen:   " + names_of(row.names_ever) + "\n";
    return out;
}

} // namespace

extern "C" {

EMSCRIPTEN_KEEPALIVE
int mc_open(const char *path) {
    g_error.clear();
    g_rows.clear();
    g_total = 0;
    if (g_db) {
        sqlite3_close(g_db);
        g_db = nullptr;
    }
    if (sqlite3_open_v2(path, &g_db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        g_error = g_db ? sqlite3_errmsg(g_db) : "could not open database";
        if (g_db) {
            sqlite3_close(g_db);
            g_db = nullptr;
        }
        return 1;
    }
    sqlite3_busy_timeout(g_db, 3000);
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, "SELECT COUNT(*) FROM servers", -1, &stmt, nullptr) != SQLITE_OK) {
        g_error = sqlite3_errmsg(g_db);
        return 1;
    }
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        g_total = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return 0;
}

EMSCRIPTEN_KEEPALIVE
void mc_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = nullptr;
    }
    g_rows.clear();
    g_total = 0;
}

EMSCRIPTEN_KEEPALIVE
int mc_apply(const char *query) {
    g_error.clear();
    if (!g_db) {
        g_error = "database not open";
        return -1;
    }
    const auto started = std::chrono::steady_clock::now();
    std::string where_sql;
    std::vector<Param> params;
    if (!compile_search(query ? query : "", where_sql, params, g_error)) {
        return -1;
    }

    std::string select =
        "SELECT ip_port, " + col_or("motd", "''") + ", " +
        col_or("players_online", "0") + ", " + col_or("max_players", "0") + ", " +
        col_or("version", "''") + ", " + col_or("cracked", "''") + ", " +
        col_or("whitelist", "''") + ", " + col_or("players_now", "'[]'") + ", " +
        col_or("players_ever", "'[]'") + ", " + col_or("first_seen", "0") + ", " +
        col_or("last_seen", "0") + ", " + col_or("times_seen", "0") + ", " +
        col_or("protocol", "0") + " FROM servers " + where_sql +
        " ORDER BY last_seen DESC";

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, select.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        g_error = sqlite3_errmsg(g_db);
        return -1;
    }
    for (size_t i = 0; i < params.size(); ++i) {
        const Param &p = params[i];
        int rc = p.text ? sqlite3_bind_text(stmt, static_cast<int>(i + 1),
                                            p.value.c_str(), -1, SQLITE_TRANSIENT)
                        : sqlite3_bind_int64(stmt, static_cast<int>(i + 1), p.number);
        if (rc != SQLITE_OK) {
            g_error = sqlite3_errmsg(g_db);
            sqlite3_finalize(stmt);
            return -1;
        }
    }

    std::vector<Row> rows;
    int step = SQLITE_ROW;
    while ((step = sqlite3_step(stmt)) == SQLITE_ROW) {
        Row row;
        row.ip = text_col(stmt, 0);
        row.motd = text_col(stmt, 1);
        row.players = sqlite3_column_int64(stmt, 2);
        row.max_players = sqlite3_column_int64(stmt, 3);
        row.version = text_col(stmt, 4);
        row.cracked = text_col(stmt, 5);
        row.whitelist = text_col(stmt, 6);
        row.names_now = text_col(stmt, 7);
        row.names_ever = text_col(stmt, 8);
        row.first_seen = sqlite3_column_double(stmt, 9);
        row.last_seen = sqlite3_column_double(stmt, 10);
        row.times_seen = sqlite3_column_int64(stmt, 11);
        row.protocol = sqlite3_column_int64(stmt, 12);
        rows.push_back(std::move(row));
    }
    if (step != SQLITE_DONE) {
        g_error = sqlite3_errmsg(g_db);
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    g_rows = std::move(rows);

    const auto elapsed = std::chrono::steady_clock::now() - started;
    g_load_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    return static_cast<int>(g_rows.size());
}

EMSCRIPTEN_KEEPALIVE
int mc_sort(const char *stack) {
    g_error.clear();
    if (!g_db) {
        g_error = "database not open";
        return -1;
    }
    std::string spec = stack ? stack : "";
    size_t start = 0;
    while (start <= spec.size()) {
        size_t comma = spec.find(',', start);
        std::string entry = spec.substr(start, comma == std::string::npos
                                                   ? std::string::npos
                                                   : comma - start);
        entry = trim(entry);
        if (!entry.empty()) {
            size_t colon = entry.rfind(':');
            std::string column = colon == std::string::npos ? entry : entry.substr(0, colon);
            std::string dir = colon == std::string::npos ? "asc" : entry.substr(colon + 1);
            column = trim(column);
            if (!valid_sort_column(column)) {
                g_error = "unknown sort column: " + column;
                return -1;
            }
            sort_by_column(column, lower_text(trim(dir)) == "desc");
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return static_cast<int>(g_rows.size());
}

EMSCRIPTEN_KEEPALIVE
int mc_count(void) {
    return static_cast<int>(g_rows.size());
}

EMSCRIPTEN_KEEPALIVE
int mc_total(void) {
    return static_cast<int>(g_total);
}

EMSCRIPTEN_KEEPALIVE
int mc_load_ms(void) {
    return static_cast<int>(g_load_ms);
}

EMSCRIPTEN_KEEPALIVE
const char *mc_error(void) {
    return g_error.c_str();
}

EMSCRIPTEN_KEEPALIVE
const char *mc_cell(int index, int column) {
    g_scratch.clear();
    if (index < 0 || static_cast<size_t>(index) >= g_rows.size()) {
        return g_scratch.c_str();
    }
    const Row &row = g_rows[static_cast<size_t>(index)];
    switch (column) {
    case 0: g_scratch = row.ip; break;
    case 1: g_scratch = clean_display(row.motd); break;
    case 2: g_scratch = std::to_string(row.players) + "/" + std::to_string(row.max_players); break;
    case 3: g_scratch = clean_display(row.version); break;
    case 4: g_scratch = clean_display(row.cracked); break;
    case 5: g_scratch = clean_display(row.whitelist); break;
    case 6: g_scratch = names_of(row.names_now); break;
    case 7: g_scratch = names_of(row.names_ever); break;
    case 8: g_scratch = timestamp_text(row.first_seen); break;
    case 9: g_scratch = timestamp_text(row.last_seen); break;
    case 10: g_scratch = std::to_string(row.times_seen); break;
    default: break;
    }
    return g_scratch.c_str();
}

EMSCRIPTEN_KEEPALIVE
const char *mc_detail(int index) {
    g_scratch.clear();
    if (index < 0 || static_cast<size_t>(index) >= g_rows.size()) {
        return g_scratch.c_str();
    }
    g_scratch = detail_text(g_rows[static_cast<size_t>(index)]);
    return g_scratch.c_str();
}

EMSCRIPTEN_KEEPALIVE
const char *mc_ip(int index) {
    g_scratch.clear();
    if (index < 0 || static_cast<size_t>(index) >= g_rows.size()) {
        return g_scratch.c_str();
    }
    g_scratch = g_rows[static_cast<size_t>(index)].ip;
    return g_scratch.c_str();
}

EMSCRIPTEN_KEEPALIVE
const char *mc_sqlite_version(void) {
    return sqlite3_libversion();
}

} // extern "C"
