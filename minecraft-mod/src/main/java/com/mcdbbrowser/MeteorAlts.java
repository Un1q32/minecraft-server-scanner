package com.mcdbbrowser;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;
import meteordevelopment.meteorclient.systems.accounts.Accounts;
import meteordevelopment.meteorclient.systems.accounts.types.CrackedAccount;
import org.jspecify.annotations.Nullable;

/** Only load this class after checking {@link #MOD_ID} is loaded; it links against Meteor Client. */
final class MeteorAlts {
	static final String MOD_ID = "meteor-client";
	private static final Pattern JAVA_USERNAME = Pattern.compile("[A-Za-z0-9_]{3,16}");

	private MeteorAlts() {
	}

	/** Runs off the render thread because Meteor saves its accounts file on every add. */
	static CompletableFuture<Result> addCracked(List<String> names) {
		return CompletableFuture.supplyAsync(() -> {
			Accounts accounts = Accounts.get();
			int added = 0;
			int alreadyPresent = 0;
			int invalid = 0;
			for (String name : names) {
				if (!JAVA_USERNAME.matcher(name).matches()) {
					invalid++;
					continue;
				}

				CrackedAccount account = new CrackedAccount(name);
				account.fetchInfo();
				if (accounts.exists(account)) {
					alreadyPresent++;
				} else {
					accounts.add(account);
					added++;
				}
			}
			return new Result(added, alreadyPresent, invalid);
		});
	}

	/** Add the name to Meteor's account manager (if needed) and sign in as it. */
	static CompletableFuture<LoginResult> loginCracked(String name) {
		return CompletableFuture.supplyAsync(() -> {
			String trimmed = name == null ? "" : name.strip();
			if (!JAVA_USERNAME.matcher(trimmed).matches()) {
				return new LoginResult(trimmed, false, false, false, "Not a valid Java username");
			}
			try {
				CrackedAccount account = new CrackedAccount(trimmed);
				if (!account.fetchInfo()) {
					return new LoginResult(trimmed, false, false, false, "Meteor could not load that name");
				}
				Accounts accounts = Accounts.get();
				boolean alreadyPresent = accounts.exists(account);
				if (!alreadyPresent) {
					accounts.add(account);
				}
				boolean loggedIn = account.login();
				if (loggedIn) {
					accounts.save();
				}
				return new LoginResult(trimmed, true, !alreadyPresent, loggedIn,
					loggedIn ? null : "Meteor rejected the login");
			} catch (Throwable throwable) {
				String message = throwable.getMessage();
				return new LoginResult(trimmed, false, false, false,
					message == null ? throwable.getClass().getSimpleName() : message);
			}
		});
	}

	record Result(int added, int alreadyPresent, int invalid) {
	}

	record LoginResult(String name, boolean valid, boolean added, boolean loggedIn,
	                   @Nullable String error) {
	}
}
