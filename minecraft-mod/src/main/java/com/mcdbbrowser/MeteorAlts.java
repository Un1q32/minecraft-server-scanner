package com.mcdbbrowser;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;
import meteordevelopment.meteorclient.systems.accounts.Accounts;
import meteordevelopment.meteorclient.systems.accounts.types.CrackedAccount;

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

	record Result(int added, int alreadyPresent, int invalid) {
	}
}
