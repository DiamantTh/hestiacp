<div class="login">
	<a href="/" class="u-block u-mb40">
		<img src="/images/logo.svg" alt="<?= tohtml($_SESSION["APP_NAME"]) ?>" width="100" height="120">
	</a>
	<form id="login-form" method="post" action="/login/">
		<input type="hidden" name="token" value="<?= tohtml($_SESSION["token"]) ?>">
		<h1 class="login-title">
			<?= tohtml(sprintf(_("Welcome to %s"), $_SESSION["APP_NAME"])) ?>
		</h1>
		<?php if (!empty($error)) { ?>
			<p class="error"><?= tohtml($error) ?></p>
		<?php } ?>
		<div id="passkey-error" class="error" style="display:none;"></div>
		<div class="u-mb20">
			<label for="username" class="form-label"><?= tohtml( _("Username")) ?></label>
			<input type="text" class="form-control" name="user" id="username" autocomplete="username" required autofocus>
		</div>
		<div class="u-side-by-side">
			<button type="submit" class="button">
				<i class="fas fa-right-to-bracket"></i><?= tohtml( _("Next")) ?>
			</button>
			<?php if (function_exists("openssl_verify")) { ?>
				<button type="button" id="passkey-login-btn" class="button button-secondary" title="<?= tohtml(_("Sign in with a passkey")) ?>">
					<i class="fas fa-key"></i><?= tohtml(_("Passkey")) ?>
				</button>
			<?php } ?>
		</div>
	</form>
</div>
<script>
(function () {
	var btn = document.getElementById("passkey-login-btn");
	if (!btn || !window.PublicKeyCredential) {
		if (btn) btn.style.display = "none";
		return;
	}
	btn.addEventListener("click", function () {
		var username = document.getElementById("username").value.trim();
		if (!username) {
			document.getElementById("passkey-error").textContent = <?= json_encode(_("Please enter your username first.")) ?>;
			document.getElementById("passkey-error").style.display = "block";
			return;
		}
		document.getElementById("passkey-error").style.display = "none";
		var token = <?= json_encode($_SESSION["token"]) ?>;
		fetch("/passkey/authenticate/?user=" + encodeURIComponent(username) + "&token=" + encodeURIComponent(token))
			.then(function (r) { return r.json(); })
			.then(function (options) {
				if (options.error) {
					document.getElementById("passkey-error").textContent = options.error;
					document.getElementById("passkey-error").style.display = "block";
					return;
				}
				// Convert base64url-encoded buffers to ArrayBuffer
				options.challenge = _b64ToBuffer(options.challenge);
				if (options.allowCredentials) {
					options.allowCredentials = options.allowCredentials.map(function (c) {
						c.id = _b64ToBuffer(c.id);
						return c;
					});
				}
				return navigator.credentials.get({ publicKey: options });
			})
			.then(function (assertion) {
				if (!assertion) return;
				var body = {
					token: token,
					id: _bufferToB64(assertion.rawId),
					clientDataJSON: _bufferToB64(assertion.response.clientDataJSON),
					authenticatorData: _bufferToB64(assertion.response.authenticatorData),
					signature: _bufferToB64(assertion.response.signature),
					userHandle: assertion.response.userHandle ? _bufferToB64(assertion.response.userHandle) : null
				};
				return fetch("/passkey/authenticate/", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify(body)
				}).then(function (r) { return r.json(); });
			})
			.then(function (result) {
				if (!result) return;
				if (result.success && result.redirect) {
					window.location.href = result.redirect;
				} else if (result.error) {
					document.getElementById("passkey-error").textContent = result.error;
					document.getElementById("passkey-error").style.display = "block";
				}
			})
			.catch(function (err) {
				if (err && err.name !== "NotAllowedError") {
					document.getElementById("passkey-error").textContent = <?= json_encode(_("Passkey authentication failed. Please try again.")) ?>;
					document.getElementById("passkey-error").style.display = "block";
				}
			});
	});

	function _b64ToBuffer(b64) {
		var bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
		var buf = new Uint8Array(bin.length);
		for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
		return buf.buffer;
	}
	function _bufferToB64(buf) {
		var bytes = new Uint8Array(buf);
		var str = "";
		for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
		return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
	}
})();
</script>
