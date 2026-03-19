<?php
/**
 * WebAuthn Passkey Deletion Endpoint
 * POST /passkey/delete/ - removes a passkey credential from a user account
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

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed"]);
    exit();
}

$input = json_decode(file_get_contents("php://input"), true);

// Support both JSON body and standard POST form
if (empty($input)) {
    $input = $_POST;
}

// Verify CSRF token
if (empty($input["token"]) || $input["token"] !== $_SESSION["token"]) {
    http_response_code(403);
    echo json_encode(["error" => "Invalid CSRF token"]);
    exit();
}

$credential_id = trim($input["credential_id"] ?? "");
if (empty($credential_id)) {
    http_response_code(400);
    echo json_encode(["error" => "Missing credential_id"]);
    exit();
}

// Determine target user
$acting_user = isset($_SESSION["look"]) && $_SESSION["look"] !== "" ? $_SESSION["look"] : $_SESSION["user"];

// Only admin can delete passkeys of other users
if (!empty($input["user"]) && $_SESSION["userContext"] === "admin") {
    $target_user = preg_replace('/[^a-zA-Z0-9._-]/', '', $input["user"]);
} else {
    $target_user = $acting_user;
}

exec(
    HESTIA_CMD .
        "v-delete-user-passkey " .
        quoteshellarg($target_user) .
        " " .
        quoteshellarg($credential_id),
    $output,
    $return_var,
);
unset($output);

if ($return_var === 0) {
    echo json_encode(["success" => true]);
} else {
    http_response_code(404);
    echo json_encode(["error" => "Passkey not found or could not be deleted"]);
}
