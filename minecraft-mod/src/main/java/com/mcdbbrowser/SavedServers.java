package com.mcdbbrowser;

import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.client.multiplayer.ServerList;

final class SavedServers {
	private SavedServers() {
	}

	static boolean contains(Minecraft minecraft, String address) {
		ServerList servers = load(minecraft);
		for (int i = 0; i < servers.size(); i++) {
			if (servers.get(i).ip.equals(address)) {
				return true;
			}
		}
		return false;
	}

	/** Returns false if the server was already saved. */
	static boolean add(Minecraft minecraft, String name, String address) {
		ServerList servers = load(minecraft);
		// Direct Connect remembers servers in a hidden list; ServerList.get(ip) searches it too, so check visibility via unhide
		if (servers.unhide(address) == null) {
			if (servers.get(address) != null) {
				return false;
			}
			servers.add(new ServerData(name, address, ServerData.Type.OTHER), false);
		}
		servers.save();
		return true;
	}

	private static ServerList load(Minecraft minecraft) {
		ServerList servers = new ServerList(minecraft);
		servers.load();
		return servers;
	}
}
