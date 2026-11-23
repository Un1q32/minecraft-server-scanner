package com.mcdbbrowser.mixin;

import com.mcdbbrowser.CrackedAutoUpdate;
import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.network.protocol.login.ClientboundHelloPacket;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Marks the pending join as online-mode when the server requests encryption. */
@Mixin(ClientHandshakePacketListenerImpl.class)
abstract class ClientHandshakePacketListenerImplMixin {
	@Inject(method = "handleHello", at = @At("HEAD"))
	private void mcdbbrowser$markEncryptionRequest(ClientboundHelloPacket packet, CallbackInfo ci) {
		CrackedAutoUpdate.onEncryptionRequest();
	}
}
