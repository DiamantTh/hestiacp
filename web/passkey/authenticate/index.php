<?php
/**
 * WebAuthn Passkey Authentication - Challenge Generation and Processing
 * GET  /passkey/authenticate/?user=USERNAME&token=CSRF - returns JSON challenge
 * POST /passkey/authenticate/ - processes the assertion response
 *
 * This endpoint is used during the login flow (NO_AUTH_REQUIRED) as well as
 * from authenticated sessions to verify a passkey.
 */

use function Hestiacp\quoteshellarg\quoteshellarg;

define("NO_AUTH_REQUIRED", true);
include $_SERVER["DOCUMENT_ROOT"] . "/inc/main.php";

header("Content-Type: application/json; charset=utf-8");

try {
    require_once dirname($_SERVER["DOCUMENT_ROOT"]) . "/inc/vendor/autoload.php";
} catch (Throwable $ex) {
    http_response_code(500);
    echo json_encode(["error" => "Unable to load WebAuthn library."]);
    exit();
}

use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\WebAuthnException;

$rp_id = $_SERVER["HTTP_HOST"];
if (str_contains($rp_id, ":")) {
    $rp_id = explode(":", $rp_id)[0];
}
$rp_name = !empty($_SESSION["APP_NAME"]) ? $_SESSION["APP_NAME"] : "Hestia Control Panel";

try {
    $webauthn = new WebAuthn($rp_name, $rp_id, ["none", "packed", "fido-u2f", "apple", "android-key", "android-safetynet", "tpm"], true);
} catch (WebAuthnException $ex) {
    http_response_code(500);
    echo json_encode(["error" => "WebAuthn initialization failed: " . $ex->getMessage()]);
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "GET") {
    // --- Challenge generation phase ---

    // Validate CSRF token
    if (empty($_GET["token"]) || $_GET["token"] !== $_SESSION["token"]) {
        http_response_code(403);
        echo json_encode(["error" => "Invalid CSRF token"]);
        exit();
    }

    // Determine which user is trying to authenticate
    $username = "";
    if (!empty($_SESSION["login"]["username"])) {
        $username = $_SESSION["login"]["username"];
    } elseif (!empty($_GET["user"])) {
        // Sanitize - same validation as login form
        if (preg_match('/^[[:alnum:]][-|\.|_[:alnum:]]{0,28}[[:alnum:]]$/', $_GET["user"])) {
            $username = $_GET["user"];
        }
    }

    if (empty($username)) {
        http_response_code(400);
        echo json_encode(["error" => "Username not specified"]);
        exit();
    }

    // Load user's passkey credential IDs
    exec(HESTIA_CMD . "v-list-user-passkeys " . quoteshellarg($username) . " json", $output, $return_var);
    $credentials = json_decode(implode("", $output), true) ?: [];
    unset($output);

    if (empty($credentials)) {
        http_response_code(404);
        echo json_encode(["error" => "No passkeys registered for this user"]);
        exit();
    }

    // Build allowed credential IDs array for the assertion request
    $allowed_ids = [];
    foreach (array_keys($credentials) as $id) {
        $decoded = base64_decode($id, true);
        $allowed_ids[] = $decoded !== false ? $decoded : $id;
    }

    $get_args = $webauthn->getGetArgs(
        $allowed_ids,
        60,
        true,   // allowUsb
        true,   // allowNfc
        true,   // allowBle
        true,   // allowHybrid
        true,   // allowInternal
        false   // requireUserVerification
    );

    $_SESSION["webauthn_challenge_auth"] = $webauthn->getChallenge();
    $_SESSION["webauthn_auth_user"] = $username;

    echo json_encode($get_args);
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // --- Assertion processing phase ---
    $input = json_decode(file_get_contents("php://input"), true);

    if (empty($input)) {
        http_response_code(400);
        echo json_encode(["error" => "Invalid request body"]);
        exit();
    }

    // Verify CSRF token
    if (empty($input["token"]) || $input["token"] !== $_SESSION["token"]) {
        http_response_code(403);
        echo json_encode(["error" => "Invalid CSRF token"]);
        exit();
    }

    if (empty($_SESSION["webauthn_challenge_auth"]) || empty($_SESSION["webauthn_auth_user"])) {
        http_response_code(400);
        echo json_encode(["error" => "No authentication challenge found. Please start over."]);
        exit();
    }

    $username = $_SESSION["webauthn_auth_user"];
    $challenge = $_SESSION["webauthn_challenge_auth"];

    // Clear challenge from session immediately to prevent replay
    unset($_SESSION["webauthn_challenge_auth"]);
    unset($_SESSION["webauthn_auth_user"]);

    // Load user credentials to find matching public key
    exec(HESTIA_CMD . "v-list-user-passkeys " . quoteshellarg($username) . " json", $output, $return_var);
    $credentials = json_decode(implode("", $output), true) ?: [];
    unset($output);

    // The credential ID returned by the authenticator.
    // The client sends the raw credential ID as base64url; we stored it as standard base64.
    // Normalize to standard base64 for lookup.
    $raw_id = $input["id"] ?? "";
    // Convert base64url to standard base64 for storage key comparison
    $credential_id_b64 = base64_encode(
        base64_decode(str_replace(["-", "_"], ["+", "/"], $raw_id) . str_repeat("=", (4 - strlen($raw_id) % 4) % 4), true) ?: ""
    );
    $credential = $credentials[$credential_id_b64] ?? null;

    if ($credential === null) {
        // Also try matching with raw id as stored
        foreach ($credentials as $stored_id => $cred) {
            if ($stored_id === $raw_id) {
                $credential = $cred;
                $credential_id_b64 = $stored_id;
                break;
            }
        }
    }

    if ($credential === null) {
        http_response_code(400);
        echo json_encode(["error" => "Unknown credential"]);
        exit();
    }

    try {
        $client_data_json = base64_decode($input["clientDataJSON"] ?? "");
        $authenticator_data = base64_decode($input["authenticatorData"] ?? "");
        $signature = base64_decode($input["signature"] ?? "");
        $public_key_pem = $credential["public_key"];
        $prev_sign_count = (int) ($credential["sign_count"] ?? 0);

        $webauthn->processGet(
            $client_data_json,
            $authenticator_data,
            $signature,
            $public_key_pem,
            $challenge,
            $prev_sign_count,
            false,  // requireUserVerification
            true    // requireUserPresent
        );
    } catch (WebAuthnException $ex) {
        $ip = $_SERVER["REMOTE_ADDR"];
        $v_user = quoteshellarg($username);
        $v_ip = quoteshellarg($ip);
        $v_session_id = quoteshellarg($_SESSION["token"] ?? "");
        $v_user_agent = quoteshellarg($_SERVER["HTTP_USER_AGENT"] ?? "");
        exec(
            HESTIA_CMD .
                "v-log-user-login " .
                $v_user .
                " " .
                $v_ip .
                " failed " .
                $v_session_id .
                " " .
                $v_user_agent .
                ' yes "WebAuthn assertion failed"',
            $output2,
            $ret2,
        );
        sleep(2);
        http_response_code(400);
        echo json_encode(["error" => "Authentication failed: " . $ex->getMessage()]);
        exit();
    }

    // Update sign count
    $new_sign_count = $webauthn->getSignatureCounter();
    exec(
        HESTIA_CMD .
            "v-update-user-passkey " .
            quoteshellarg($username) .
            " " .
            quoteshellarg($credential_id_b64) .
            " " .
            quoteshellarg((string) $new_sign_count),
        $output,
        $return_var,
    );
    unset($output);

    // Verify user account status before creating session
    exec(HESTIA_CMD . "v-list-user " . quoteshellarg($username) . " json", $output, $return_var);
    if ($return_var !== 0) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid username or account unavailable"]);
        exit();
    }
    $data = json_decode(implode("", $output), true);
    unset($output);

    if ($data[$username]["LOGIN_DISABLED"] === "yes") {
        sleep(2);
        http_response_code(401);
        echo json_encode(["error" => "Login disabled for this account"]);
        exit();
    }

    if ($data[$username]["SUSPENDED"] === "yes") {
        sleep(2);
        http_response_code(401);
        echo json_encode(["error" => "Account suspended"]);
        exit();
    }

    // Establish session
    $_SESSION["user"] = $username;
    $_SESSION["LAST_ACTIVITY"] = time();
    $_SESSION["userContext"] = $data[$username]["ROLE"];
    $_SESSION["userTheme"] = $data[$username]["THEME"];
    if ($_SESSION["POLICY_USER_CHANGE_THEME"] !== "yes") {
        unset($_SESSION["userTheme"]);
    }
    $_SESSION["userSortOrder"] = !empty($data[$username]["PREF_UI_SORT"])
        ? $data[$username]["PREF_UI_SORT"]
        : "name";

    // Set language
    exec(HESTIA_CMD . "v-list-sys-languages json", $langOutput, $langReturn);
    $languages = json_decode(implode("", $langOutput), true);
    unset($langOutput);
    $_SESSION["language"] = in_array($data[$username]["LANGUAGE"], $languages)
        ? $data[$username]["LANGUAGE"]
        : "en";

    // Regenerate session ID to prevent fixation
    session_regenerate_id(true);

    // Log successful login
    $ip = $_SERVER["REMOTE_ADDR"];
    $v_user = quoteshellarg($username);
    $v_ip = quoteshellarg($ip);
    $v_session_id = quoteshellarg($_SESSION["token"] ?? "");
    $v_user_agent = quoteshellarg($_SERVER["HTTP_USER_AGENT"] ?? "");
    exec(
        HESTIA_CMD .
            "v-log-user-login " .
            $v_user .
            " " .
            $v_ip .
            " success " .
            $v_session_id .
            " " .
            $v_user_agent,
        $output,
        $return_var,
    );
    unset($output);

    // Determine redirect URL
    $redirect = "/login/";
    if (!empty($_SESSION["request_uri"])) {
        $redirect = $_SESSION["request_uri"];
        unset($_SESSION["request_uri"]);
    } elseif ($_SESSION["userContext"] === "admin") {
        $redirect = "/list/user/";
    } elseif ($data[$username]["WEB_DOMAINS"] != "0") {
        $redirect = "/list/web/";
    } elseif ($data[$username]["DNS_DOMAINS"] != "0") {
        $redirect = "/list/dns/";
    } elseif ($data[$username]["MAIL_DOMAINS"] != "0") {
        $redirect = "/list/mail/";
    } elseif ($data[$username]["DATABASES"] != "0") {
        $redirect = "/list/db/";
    } elseif ($data[$username]["CRON_JOBS"] != "0") {
        $redirect = "/list/cron/";
    } elseif ($data[$username]["BACKUPS"] != "0") {
        $redirect = "/list/backup/";
    } else {
        $redirect = "/error/";
    }

    echo json_encode(["success" => true, "redirect" => $redirect]);
    exit();
}

http_response_code(405);
echo json_encode(["error" => "Method not allowed"]);
