package com.mcdbbrowser.mixin;

import com.mcdbbrowser.ConnectionHistory;
import com.mcdbbrowser.WhitelistAutoUpdate;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screens.ConnectScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.client.multiplayer.TransferState;
import net.minecraft.client.multiplayer.resolver.ServerAddress;
import org.jspecify.annotations.Nullable;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Every way of joining a server goes through startConnecting, so attempts are logged even if they then fail. */
@Mixin(ConnectScreen.class)
abstract class ConnectScreenMixin {
	@Inject(method = "startConnecting", at = @At("HEAD"))
	private static void mcdbbrowser$logAttempt(Screen parent, Minecraft minecraft, ServerAddress address, @Nullable ServerData server, boolean quickPlay, @Nullable TransferState transferState, CallbackInfo ci) {
		if (server != null && !server.isRealm()) {
			ConnectionHistory.add(server.name, server.ip);
			WhitelistAutoUpdate.track(server.ip);
		}
	}
}
