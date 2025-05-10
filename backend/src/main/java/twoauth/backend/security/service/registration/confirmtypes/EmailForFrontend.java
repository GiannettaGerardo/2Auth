package twoauth.backend.security.service.registration.confirmtypes;

import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

public final class EmailForFrontend extends JwtsHS512Token
{
    private final JavaMailSender mailSender;
    private final String userEmail;

    public EmailForFrontend(final JavaMailSender mailSender, final String userEmail) {
        super();
        this.mailSender = mailSender;
        this.userEmail = userEmail;
    }

    @Override
    public boolean sendConfirmationRequest()
    {
        System.out.printf("EmailForFrontend: %s%n", uniqueSecureToken);

        final SimpleMailMessage emailMessage = new SimpleMailMessage();
        emailMessage.setTo(userEmail);
        emailMessage.setSubject("Confirm Registration");
        emailMessage.setText(String.format("Insert this registration token in the next login: %s", uniqueSecureToken));

        try {
            mailSender.send(emailMessage);
        }
        catch (MailException e) {
            System.err.printf("EmailForFrontend JavaMailSender.send: %s - %s%n", userEmail, e.getMessage());
            return false;
        }
        System.out.printf("Email sent: %s%n", emailMessage);
        /*try {
            executor.submit(() -> {
                try {
                    mailSender.send(emailMessage);
                    System.out.printf("Email sent: %s%n", emailMessage);
                }
                catch (MailException e) {
                    System.err.printf("EmailForFrontend JavaMailSender.send: %s - %s%n", userEmail, e.getMessage());
                }
            });
        }
        catch (RejectedExecutionException e) {
            System.err.printf("EmailForFrontend executor.submit: %s - %s%n", userEmail, e.getMessage());
            return false;
        }*/
        return true;
    }

    @Override
    public String toString() {
        return "EmailForFrontend{" +
                "userEmail='" + userEmail + '\'' +
                ", uniqueSecureToken='" + uniqueSecureToken + '\'' +
                '}';
    }
}
