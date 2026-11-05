package com.mcdbbrowser.mixin;

import com.mcdbbrowser.WhitelistAutoUpdate;
import net.minecraft.client.gui.screens.DisconnectedScreen;
import net.minecraft.network.DisconnectionDetails;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Login rejections and in-game disconnects both end up on DisconnectedScreen. */
@Mixin(DisconnectedScreen.class)
abstract class DisconnectedScreenMixin {
	@Shadow
	@Final
	private DisconnectionDetails details;

	@Inject(method = "init", at = @At("HEAD"))
	private void mcdbbrowser$recordWhitelistRejection(CallbackInfo ci) {
		WhitelistAutoUpdate.onDisconnected(this.details.reason());
	}
}
