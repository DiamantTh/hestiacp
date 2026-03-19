<?php
/**
 * WebAuthn Passkey Registration - Challenge Generation and Processing
 * GET  /passkey/register/ - returns a JSON challenge for credential creation
 * POST /passkey/register/ - processes the credential creation response
 */

use function Hestiacp\quoteshellarg\quoteshellarg;

// Main include (requires authenticated session)
include $_SERVER["DOCUMENT_ROOT"] . "/inc/main.php";

header("Content-Type: application/json; charset=utf-8");

// Require active session
if (!isset($_SESSION["user"])) {
    http_response_code(401);
    echo json_encode(["error" => "Not authenticated"]);
    exit();
}

try {
    require_once dirname($_SERVER["DOCUMENT_ROOT"]) . "/inc/vendor/autoload.php";
} catch (Throwable $ex) {
    http_response_code(500);
    echo json_encode(["error" => "Unable to load WebAuthn library. Please run v-add-sys-dependencies."]);
    exit();
}

use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\WebAuthnException;

$acting_user = isset($_SESSION["look"]) && $_SESSION["look"] !== "" ? $_SESSION["look"] : $_SESSION["user"];
$rp_id = $_SERVER["HTTP_HOST"];
// Strip port from rp_id
if (str_contains($rp_id, ":")) {
    $rp_id = explode(":", $rp_id)[0];
}
$rp_name = !empty($_SESSION["APP_NAME"]) ? $_SESSION["APP_NAME"] : "Hestia Control Panel";

// Only admin can manage passkeys of other users; regular users manage only their own
if ($_SESSION["userContext"] !== "admin" && !empty($_SESSION["look"])) {
    http_response_code(403);
    echo json_encode(["error" => "Forbidden"]);
    exit();
}

try {
    $webauthn = new WebAuthn($rp_name, $rp_id, ["none", "packed", "fido-u2f", "apple", "android-key", "android-safetynet", "tpm"], true);
} catch (WebAuthnException $ex) {
    http_response_code(500);
    echo json_encode(["error" => "WebAuthn initialization failed: " . $ex->getMessage()]);
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "GET") {
    // --- Challenge generation phase ---

    // Verify CSRF token passed as query parameter
    if (empty($_GET["token"]) || $_GET["token"] !== $_SESSION["token"]) {
        http_response_code(403);
        echo json_encode(["error" => "Invalid CSRF token"]);
        exit();
    }

    // Load existing credential IDs to exclude (prevent re-registration)
    $exclude_ids = [];
    exec(HESTIA_CMD . "v-list-user-passkeys " . quoteshellarg($acting_user) . " json", $output, $return_var);
    $existing = json_decode(implode("", $output), true) ?: [];
    unset($output);
    foreach (array_keys($existing) as $id) {
        $exclude_ids[] = base64_decode($id, true) !== false ? base64_decode($id) : $id;
    }

    $user_id = hash("sha256", $acting_user, true);

    $create_args = $webauthn->getCreateArgs(
        $user_id,
        $acting_user,
        $acting_user,
        60,
        false,  // requireResidentKey
        false,  // requireUserVerification
        null,
        $exclude_ids
    );

    // Store challenge in session for later verification
    $_SESSION["webauthn_challenge_register"] = $webauthn->getChallenge();
    $_SESSION["webauthn_register_user"] = $acting_user;

    echo json_encode($create_args);
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // --- Credential processing phase ---
    $input = json_decode(file_get_contents("php://input"), true);

    if (empty($input)) {
        http_response_code(400);
        echo json_encode(["error" => "Invalid request body"]);
        exit();
    }

    // Verify CSRF token from JSON body
    if (empty($input["token"]) || $input["token"] !== $_SESSION["token"]) {
        http_response_code(403);
        echo json_encode(["error" => "Invalid CSRF token"]);
        exit();
    }

    if (empty($_SESSION["webauthn_challenge_register"])) {
        http_response_code(400);
        echo json_encode(["error" => "No registration challenge found. Please start over."]);
        exit();
    }

    $target_user = $_SESSION["webauthn_register_user"] ?? $acting_user;
    $challenge = $_SESSION["webauthn_challenge_register"];

    // Clear challenge from session
    unset($_SESSION["webauthn_challenge_register"]);
    unset($_SESSION["webauthn_register_user"]);

    try {
        $client_data_json = base64_decode($input["clientDataJSON"] ?? "");
        $attestation_object = base64_decode($input["attestationObject"] ?? "");

        $data = $webauthn->processCreate(
            $client_data_json,
            $attestation_object,
            $challenge,
            false,  // requireUserVerification
            true,   // requireUserPresent
            false   // failIfRootMismatch
        );
    } catch (WebAuthnException $ex) {
        http_response_code(400);
        echo json_encode(["error" => "Registration failed: " . $ex->getMessage()]);
        exit();
    }

    // Encode credential ID as URL-safe base64
    $credential_id = base64_encode($data->credentialId);
    $public_key_pem = $data->publicKeyPem;
    $sign_count = $data->signatureCounter ?? 0;

    // Validate and sanitize the passkey name provided by the user
    $passkey_name = trim($input["name"] ?? "");
    if (empty($passkey_name)) {
        http_response_code(400);
        echo json_encode(["error" => "Passkey name is required"]);
        exit();
    }
    if (strlen($passkey_name) > 64) {
        http_response_code(400);
        echo json_encode(["error" => "Passkey name must not exceed 64 characters"]);
        exit();
    }
    $sanitized_name = preg_replace('/[^a-zA-Z0-9 _.@-]/', '', $passkey_name);
    if (empty($sanitized_name)) {
        $sanitized_name = "Passkey " . date("Y-m-d");
    }

    // Store credential via bin command
    exec(
        HESTIA_CMD .
            "v-add-user-passkey " .
            quoteshellarg($target_user) .
            " " .
            quoteshellarg($credential_id) .
            " " .
            quoteshellarg($public_key_pem) .
            " " .
            quoteshellarg((string) $sign_count) .
            " " .
            quoteshellarg($sanitized_name),
        $output,
        $return_var,
    );
    unset($output);

    if ($return_var !== 0) {
        http_response_code(500);
        echo json_encode(["error" => "Failed to store passkey credential"]);
        exit();
    }

    echo json_encode(["success" => true, "name" => $sanitized_name]);
    exit();
}

http_response_code(405);
echo json_encode(["error" => "Method not allowed"]);
