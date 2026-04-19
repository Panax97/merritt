<?php

declare(strict_types=1);

// =====================================
// Merritt Collections Contact Processor
// PHPMailer + Hostinger SMTP + Anti-Spam
// =====================================

require __DIR__ . '/vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// ---------- CONFIG ----------
const SMTP_HOST = 'smtp.hostinger.com';
const SMTP_PORT = 465;
const SMTP_USERNAME = 'hello@themerrittcollections.com';
const SMTP_PASSWORD = 'IpZ]scb6$I';
const SMTP_FROM_EMAIL = 'hello@themerrittcollections.com';
const SMTP_FROM_NAME = 'The Merritt Collections';
const DESTINATION_EMAIL = 'hello@themerrittcollections.com';
const DESTINATION_NAME = 'The Merritt Collections';
const MIN_FORM_FILL_MS = 3000;
const MAX_MESSAGE_LENGTH = 3000;

// Bloquea algunos dominios desechables comunes
$blockedDomains = [
    'mailinator.com',
    '10minutemail.com',
    'guerrillamail.com',
    'tempmail.com',
    'yopmail.com',
    'sharklasers.com',
];

// ==============================
// HELPERS
// ==============================
function respondText(string $message, int $statusCode = 200): never
{
    http_response_code($statusCode);
    header('Content-Type: text/plain; charset=UTF-8');
    echo $message;
    exit;
}

function post(string $key): string
{
    return trim((string)($_POST[$key] ?? ''));
}

function containsSuspiciousLinks(string $text): bool
{
    return (bool) preg_match('/https?:\/\/|www\.|<a\s+href=|\[url=|bit\.ly|tinyurl|t\.co/i', $text);
}

function emailDomain(string $email): string
{
    $parts = explode('@', $email);
    return strtolower($parts[1] ?? '');
}

// ==============================
// REQUEST METHOD
// ==============================
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respondText('Invalid request method.', 405);
}

// ==============================
// ANTI-SPAM
// ==============================
$honeypot = post('website_url');
if ($honeypot !== '') {
    respondText('Spam detected.', 403);
}

$formStartedAt = post('form_started_at');
if ($formStartedAt === '' || !ctype_digit($formStartedAt)) {
    respondText('Invalid form submission.', 400);
}

$startedAtMs = (int) $formStartedAt;
$nowMs = (int) round(microtime(true) * 1000);

if (($nowMs - $startedAtMs) < MIN_FORM_FILL_MS) {
    respondText('Form submitted too quickly.', 403);
}

// ==============================
// INPUTS
// ==============================
$firstName         = post('first_name');
$lastName          = post('last_name');
$userEmail         = post('user_email');
$phoneNumber       = post('phone_number');
$serviceInterested = post('service_interested');
$propertyDetails   = post('property_details');

$fullName = trim($firstName . ' ' . $lastName);
$subjectLine = 'New Consultation Request - ' . $serviceInterested;

// ==============================
// VALIDATION
// ==============================
if ($firstName === '' || $lastName === '' || $userEmail === '' || $serviceInterested === '' || $propertyDetails === '') {
    respondText('Please complete all required fields.', 422);
}

if (mb_strlen($firstName) < 2 || mb_strlen($firstName) > 80) {
    respondText('Please enter a valid first name.', 422);
}

if (mb_strlen($lastName) < 2 || mb_strlen($lastName) > 80) {
    respondText('Please enter a valid last name.', 422);
}

if (!filter_var($userEmail, FILTER_VALIDATE_EMAIL)) {
    respondText('Please enter a valid email address.', 422);
}

if ($phoneNumber !== '' && mb_strlen($phoneNumber) > 40) {
    respondText('Please enter a valid phone number.', 422);
}

if (mb_strlen($serviceInterested) < 3 || mb_strlen($serviceInterested) > 120) {
    respondText('Please select a valid service.', 422);
}

if (mb_strlen($propertyDetails) < 10 || mb_strlen($propertyDetails) > MAX_MESSAGE_LENGTH) {
    respondText('Please enter valid property details.', 422);
}

if (containsSuspiciousLinks($propertyDetails)) {
    respondText('Links are not allowed in the message.', 403);
}

$domain = emailDomain($userEmail);
if (in_array($domain, $blockedDomains, true)) {
    respondText('Please use a business or personal email address.', 403);
}

// ==============================
// SANITIZE
// ==============================
$safeFullName = htmlspecialchars($fullName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$safeEmail = htmlspecialchars($userEmail, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$safePhone = htmlspecialchars($phoneNumber, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$safeService = htmlspecialchars($serviceInterested, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$safeDetails = htmlspecialchars($propertyDetails, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

// ==============================
// SEND EMAIL
// ==============================
$mail = new PHPMailer(true);

try {
    $mail->isSMTP();
    $mail->Host       = SMTP_HOST;
    $mail->SMTPAuth   = true;
    $mail->Username   = SMTP_USERNAME;
    $mail->Password   = SMTP_PASSWORD;
    $mail->Port       = SMTP_PORT;
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
    $mail->CharSet    = 'UTF-8';

    // Si 465 no funciona, usa esto:
    // $mail->Port = 587;
    // $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;

    $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
    $mail->addAddress(DESTINATION_EMAIL, DESTINATION_NAME);
    $mail->addReplyTo($userEmail, $fullName);

    $mail->Subject = '[Merritt Collections] ' . $subjectLine;

    $mailBodyHtml = "
        <h2>New Consultation Request from Website</h2>
        <p><strong>Full Name:</strong> {$safeFullName}</p>
        <p><strong>Email:</strong> {$safeEmail}</p>
        <p><strong>Phone:</strong> {$safePhone}</p>
        <p><strong>Service Interested In:</strong> {$safeService}</p>
        <p><strong>Property Details:</strong></p>
        <p>" . nl2br($safeDetails) . "</p>
        <hr>
        <p style='font-size:12px;color:#666;'>
            Sent from The Merritt Collections website contact form.
        </p>
    ";

    $mailBodyText =
        "New Consultation Request from Website\n\n" .
        "Full Name: {$fullName}\n" .
        "Email: {$userEmail}\n" .
        "Phone: {$phoneNumber}\n" .
        "Service Interested In: {$serviceInterested}\n\n" .
        "Property Details:\n{$propertyDetails}\n";

    $mail->isHTML(true);
    $mail->Body    = $mailBodyHtml;
    $mail->AltBody = $mailBodyText;

    $mail->send();

    respondText('OK');
} catch (Exception $e) {
    respondText('We could not send your message right now. Please try again later.', 500);
}