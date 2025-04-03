<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $to = "renishs.22msc@kongu.edu@gmail.com"; // Change this to your email
    $subject = "New Contact Form Submission";
    $message = "Name: " . $_POST['fullName'] . "\n";
    $message .= "Email: " . $_POST['email'] . "\n";
    $message .= "Phone: " . $_POST['phone'] . "\n";
    $message .= "Address: " . $_POST['address'] . "\n";
    $message .= "Message: " . $_POST['message'];

    $headers = "From: " . $_POST['email'];

    if (mail($to, $subject, $message, $headers)) {
        echo "Message Sent Successfully!";
    } else {
        echo "Message sending failed.";
    }
}
?>
